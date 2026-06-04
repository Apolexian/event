// hook_network.js
// Captures game-server API traffic via multiple layers:
//
// Layer 0: libnative.dll — hooks the game's own decryption/decompression
//          function to capture clean, decrypted MsgPack data. This is the
//          most reliable method (inspired by CarrotJuicer).
//
// Layer 1: SSL_read / SSL_write — hooks the TLS library to capture raw
//          decrypted HTTP traffic (request + response bytes). Works
//          regardless of the game's HTTP/serialisation stack.
//
// Layer 2: MsgPack Formatters — hooks Gallop.MsgPack.Formatters.*.Serialize
//          and *.Deserialize methods at the il2cpp level. Gives us the
//          class name of each request/response so we know *what* API call
//          is happening (e.g. SingleModeGainSkillsRequest).
//
// Layer 3: Request/Response Task pipeline — hooks the *Task classes that
//          orchestrate API calls, capturing which endpoint is being called.
//
// Loaded after il2cpp_helpers.js inside a collector IIFE.

(function () {
    "use strict";

    console.log("[network] Initialising network capture...");

    let hookCount = 0;

    // ── Global sequence counter & request ID pairing ──────────────────
    // Every event gets a monotonic _seq so the Python side can order them
    // and pair request→response even across interleaved hooks.
    var _seq = 0;
    var _nextReqId = 0;
    // apiName → reqId (most recent Send for that API)
    var _pendingReqIds = Object.create(null);

    // ══════════════════════════════════════════════════════════════════
    // LAYER 0: libnative.dll LZ4 hooks (request + response)
    // ══════════════════════════════════════════════════════════════════
    //
    // The game uses libnative.dll for packet encryption/decryption.
    // CarrotJuicer hooks both LZ4 functions:
    //   - LZ4_decompress_safe  — response (server → game, after decrypt)
    //   - LZ4_compress_default — request  (game → server, before encrypt)
    //
    // Both give us clean, plaintext MsgPack data.
    //
    // Request data has a blob1 header (4-byte LE offset, then UDID,
    // session_id, response_key) followed by the MsgPack body at
    // offset+4. We extract the crypto material from blob1 so we can
    // decode SSL-layer captures offline.

    var libnativeHooked = false;

    // ── Extracted crypto material (from blob1 request headers) ────────
    var _lastUdidHex = null; // 16 bytes → 32 hex chars
    var _lastSessionIdHex = null; // 16 bytes → 32 hex chars
    var _lastResponseKeyHex = null; // 32 bytes → 64 hex chars
    var _extractedSalt = null; // ASCII salt string from GameAssembly.dll

    try {
        var libnative = Process.getModuleByName("libnative.dll");
        if (libnative) {
            console.log("[network] Found libnative.dll at " + libnative.base);

            // ── LZ4_decompress_safe: response capture ─────────────────
            var lz4Addr = libnative.findExportByName("LZ4_decompress_safe");
            if (!lz4Addr) {
                // Some builds export it as LZ4_decompress_safe_ext
                lz4Addr = libnative.findExportByName("LZ4_decompress_safe_ext");
            }
            if (lz4Addr) {
                Interceptor.attach(lz4Addr, {
                    onEnter: function (args) {
                        this.src = args[0];
                        this.dst = args[1];
                        this.srcSize = args[2].toInt32();
                        this.dstCapacity = args[3].toInt32();
                    },
                    onLeave: function (retval) {
                        var decompressedSize = retval.toInt32();
                        if (decompressedSize <= 0 || decompressedSize > 4194304) return;

                        try {
                            var captureLen = Math.min(decompressedSize, 524288);
                            var data = this.dst.readByteArray(captureLen);
                            send(
                                {
                                    type: "collect",
                                    domain: "network",
                                    data: {
                                        _seq: _seq++,
                                        event: "libnative_decrypt",
                                        direction: "in",
                                        bytes: decompressedSize,
                                        captured: captureLen,
                                        truncated: decompressedSize > captureLen,
                                        srcSize: this.srcSize,
                                    },
                                },
                                data,
                            );
                        } catch (e) {}
                    },
                });
                hookCount++;
                libnativeHooked = true;
                console.log("[network] Hooked libnative.dll LZ4_decompress_safe");
            }

            // ── LZ4_compress_default: request capture ─────────────────
            // The input to LZ4 compress is the full request blob:
            //   bytes[0:4]       = LE uint32 blob1 length (typically 166)
            //   bytes[4:4+len]   = blob1 header (session_id, udid, response_key, auth_key)
            //   bytes[4+len:]    = MsgPack request body
            var lz4CompAddr = libnative.findExportByName("LZ4_compress_default");
            if (!lz4CompAddr) {
                lz4CompAddr = libnative.findExportByName("LZ4_compress_default_ext");
            }
            if (lz4CompAddr) {
                Interceptor.attach(lz4CompAddr, {
                    onEnter: function (args) {
                        var src = args[0];
                        var srcSize = args[2].toInt32();
                        if (srcSize <= 0 || srcSize > 4194304) return;

                        try {
                            var captureLen = Math.min(srcSize, 524288);
                            var data = src.readByteArray(captureLen);

                            // ── Parse blob1 header for crypto material ────
                            // blob1 layout: [4-byte LE offset][blob1 bytes][MsgPack body]
                            // blob1 tail (last N bytes): session_id(16) + udid(16) + response_key(32) [+ auth_key(48)]
                            var cryptoInfo = null;
                            if (srcSize > 170) {
                                try {
                                    var headerLen = src.readU32();
                                    // Sanity: typical header is 166 bytes, range 100-500
                                    if (
                                        headerLen >= 64 &&
                                        headerLen <= 500 &&
                                        headerLen + 4 < srcSize
                                    ) {
                                        var blob1End = 4 + headerLen;
                                        // The crypto fields are at the END of blob1:
                                        //   session_id: 16 bytes
                                        //   udid_raw:   16 bytes
                                        //   response_key: 32 bytes
                                        //   auth_key:   48 bytes (optional)
                                        // Total with auth: 112, without: 64
                                        var tailSize = headerLen >= 112 + 4 ? 112 : 64;
                                        if (headerLen >= tailSize) {
                                            var tailStart = blob1End - tailSize;
                                            var sessionId = src.add(tailStart).readByteArray(16);
                                            var udidRaw = src.add(tailStart + 16).readByteArray(16);
                                            var responseKey = src
                                                .add(tailStart + 32)
                                                .readByteArray(32);

                                            // Convert to hex strings
                                            var sidArr = new Uint8Array(sessionId);
                                            var udidArr = new Uint8Array(udidRaw);
                                            var rkArr = new Uint8Array(responseKey);

                                            function toHex(arr) {
                                                var h = "";
                                                for (var i = 0; i < arr.length; i++) {
                                                    var b = arr[i].toString(16);
                                                    h += b.length < 2 ? "0" + b : b;
                                                }
                                                return h;
                                            }

                                            _lastSessionIdHex = toHex(sidArr);
                                            _lastUdidHex = toHex(udidArr);
                                            _lastResponseKeyHex = toHex(rkArr);

                                            // Format UDID as UUID: 8-4-4-4-12
                                            var u = _lastUdidHex;
                                            var udidUuid =
                                                u.slice(0, 8) +
                                                "-" +
                                                u.slice(8, 12) +
                                                "-" +
                                                u.slice(12, 16) +
                                                "-" +
                                                u.slice(16, 20) +
                                                "-" +
                                                u.slice(20, 32);

                                            cryptoInfo = {
                                                headerLen: headerLen,
                                                sessionId: _lastSessionIdHex,
                                                udid: udidUuid,
                                                responseKey: _lastResponseKeyHex,
                                            };
                                        }
                                    }
                                } catch (e) {
                                    console.log("[network] blob1 parse error: " + e);
                                }
                            }

                            var record = {
                                _seq: _seq++,
                                event: "libnative_encrypt",
                                direction: "out",
                                bytes: srcSize,
                                captured: captureLen,
                                truncated: srcSize > captureLen,
                            };
                            if (cryptoInfo) record.crypto = cryptoInfo;
                            if (_extractedSalt) record.salt = _extractedSalt;

                            send(
                                {
                                    type: "collect",
                                    domain: "network",
                                    data: record,
                                },
                                data,
                            );
                        } catch (e) {}
                    },
                });
                hookCount++;
                libnativeHooked = true;
                console.log(
                    "[network] Hooked libnative.dll LZ4_compress_default (request capture)",
                );
            }

            // Also scan for exported functions that look like encrypt/decrypt
            var exports = libnative.enumerateExports();
            for (var ei = 0; ei < exports.length; ei++) {
                var exp = exports[ei];
                console.log("[network] libnative export: " + exp.name + " @ " + exp.address);
            }
        }
    } catch (e) {
        console.log("[network] libnative.dll not found or hook failed: " + e);
    }

    // ══════════════════════════════════════════════════════════════════
    // LAYER 0.5: Auto-extract crypto salt from game binary
    // ══════════════════════════════════════════════════════════════════
    //
    // The game uses a hardcoded ASCII salt for MD5-based session ID
    // generation: MD5(viewerId + udid + SALT). This salt is embedded
    // in GameAssembly.dll and can change with game updates.
    //
    // We scan the binary for it so Clairvoyance stays resilient to
    // updates without manual intervention.
    //
    // Strategy 1: Scan for the known salt string.
    // Strategy 2: If that fails, look for short ASCII strings near
    //             MD5/crypto code patterns (future heuristic).

    (function extractSalt() {
        // Known salt values (current + historical)
        var knownSalts = [
            "co!=Y;(UQCGxJ_n82", // current as of 2025
        ];

        var gameAssembly = null;
        try {
            gameAssembly = Process.getModuleByName("GameAssembly.dll");
        } catch (e) {}
        if (!gameAssembly) {
            try {
                gameAssembly = Process.getModuleByName("libil2cpp.so");
            } catch (e) {}
        }

        if (!gameAssembly) {
            console.log("[network] GameAssembly not found — salt extraction skipped");
            return;
        }

        console.log("[network] Scanning " + gameAssembly.name + " for crypto salt...");

        // Strategy 1: Scan for each known salt string
        for (var si = 0; si < knownSalts.length; si++) {
            var saltStr = knownSalts[si];
            var pattern = "";
            for (var ci = 0; ci < saltStr.length; ci++) {
                if (ci > 0) pattern += " ";
                var byte = saltStr.charCodeAt(ci).toString(16);
                pattern += (byte.length < 2 ? "0" : "") + byte;
            }

            try {
                var matches = Memory.scanSync(gameAssembly.base, gameAssembly.size, pattern);
                if (matches.length > 0) {
                    _extractedSalt = saltStr;
                    console.log(
                        "[network] ✓ Found salt '" +
                            saltStr +
                            "' at " +
                            matches[0].address +
                            " (" +
                            matches.length +
                            " occurrences)",
                    );

                    // Report to Python side
                    send({
                        type: "collect",
                        domain: "network",
                        data: {
                            _seq: _seq++,
                            event: "crypto_salt_found",
                            salt: saltStr,
                            source: "known_pattern",
                            module: gameAssembly.name,
                            address: matches[0].address.toString(),
                            occurrences: matches.length,
                        },
                    });
                    return;
                }
            } catch (e) {
                console.log("[network] Salt scan error: " + e);
            }
        }

        // Strategy 2: Heuristic — look for il2cpp string literals that
        // look like a salt (short, has special chars, near MD5 code).
        // We scan for UTF-16LE strings (il2cpp string objects) matching
        // a salt-like pattern: 14-24 chars, contains =, ;, (, or !
        // This is a best-effort fallback.
        try {
            // Look for the C# string object pattern for the salt.
            // IL2CPP strings are: [klass_ptr(8)][monitor(8)][length(4)][UTF-16LE chars...]
            // The known salt "co!=Y;(UQCGxJ_n82" in UTF-16LE:
            // 63 00 6f 00 21 00 3d 00 59 00 3b 00 28 00 ...
            // We search for the first 8 chars in UTF-16LE as a signature.
            var sig16 = "";
            var probe = "co!=Y;(U"; // first 8 chars — unique enough
            for (var pi = 0; pi < probe.length; pi++) {
                if (pi > 0) sig16 += " ";
                var ch = probe.charCodeAt(pi).toString(16);
                sig16 += (ch.length < 2 ? "0" : "") + ch + " 00";
            }
            var utf16Matches = Memory.scanSync(gameAssembly.base, gameAssembly.size, sig16);
            if (utf16Matches.length > 0) {
                // Read back the full string
                try {
                    var strAddr = utf16Matches[0].address;
                    // Read up to 32 UTF-16LE chars
                    var chars = [];
                    for (var ri = 0; ri < 32; ri++) {
                        var wchar = strAddr.add(ri * 2).readU16();
                        if (wchar === 0 || wchar > 127) break;
                        chars.push(String.fromCharCode(wchar));
                    }
                    if (chars.length >= 10) {
                        _extractedSalt = chars.join("");
                        console.log(
                            "[network] ✓ Found salt (UTF-16 heuristic): '" + _extractedSalt + "'",
                        );
                        send({
                            type: "collect",
                            domain: "network",
                            data: {
                                _seq: _seq++,
                                event: "crypto_salt_found",
                                salt: _extractedSalt,
                                source: "utf16_heuristic",
                                module: gameAssembly.name,
                                address: strAddr.toString(),
                                occurrences: utf16Matches.length,
                            },
                        });
                        return;
                    }
                } catch (e) {}
            }
        } catch (e) {
            console.log("[network] UTF-16 salt heuristic error: " + e);
        }

        console.log(
            "[network] Salt not found in " +
                gameAssembly.name +
                " (will still work via Layer 0 hooks)",
        );
    })();

    // ══════════════════════════════════════════════════════════════════
    // LAYER 1: SSL_read / SSL_write hooks
    // ══════════════════════════════════════════════════════════════════
    //
    // Unity games bundle a TLS library (BoringSSL/OpenSSL). We scan all
    // loaded modules for SSL_read and SSL_write exports. These operate
    // on plaintext — the data has already been decrypted (read) or is
    // about to be encrypted (write).
    //
    // Includes HTTP chunk reassembly: TLS writes are buffered per-connection
    // and only processed as complete HTTP messages (tracking Content-Length).
    // This prevents fragmented captures and enables credential extraction
    // at the SSL layer as a fallback when Layer 0 (libnative) isn't available.

    // ── HTTP chunk reassembly state ──────────────────────────────────
    // Per-connection buffers that accumulate TLS write data and emit
    // complete HTTP requests once Content-Length is satisfied.
    var _sslWriteBuffers = Object.create(null);

    function _hexFromBytes(arr) {
        var h = "";
        for (var i = 0; i < arr.length; i++) {
            var b = arr[i].toString(16);
            h += b.length < 2 ? "0" + b : b;
        }
        return h;
    }

    function _b64Decode(s) {
        var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        var out = [];
        var buffer = 0;
        var bits = 0;
        for (var i = 0; i < s.length; i++) {
            var c = s.charAt(i);
            if (c === "=") break;
            var idx = chars.indexOf(c);
            if (idx < 0) continue;
            buffer = (buffer << 6) | idx;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out.push((buffer >> bits) & 255);
            }
        }
        return out;
    }

    /**
     * Extract credentials from a base64-encoded request body.
     * The game packs requests as: base64(LE_u32(headerLen) + blob1 + encrypted_body)
     * blob1 tail contains: session_id(16) + udid(16) + response_key(32) [+ auth_key(48)]
     */
    function _extractCredsFromBody(bodyStr) {
        try {
            var decoded = _b64Decode(bodyStr.trim());
            if (decoded.length < 140) return null;
            var headerLen = decoded[0] | (decoded[1] << 8) | (decoded[2] << 16) | (decoded[3] << 24);
            var blob1End = 4 + headerLen;
            if (headerLen < 120 || headerLen > 2048 || decoded.length < blob1End) return null;

            // UDID is 16 bytes at offset blob1End - 96
            var udidHex = "";
            for (var i = blob1End - 96; i < blob1End - 80; i++) udidHex += _hexFromBytes([decoded[i]]);
            // Auth key is 48 bytes at the end of blob1
            var authHex = "";
            for (var j = blob1End - 48; j < blob1End; j++) authHex += _hexFromBytes([decoded[j]]);

            if (!authHex || authHex.length < 64 || udidHex.length !== 32) return null;

            // Format UDID as UUID
            var u = udidHex;
            var udidUuid = u.slice(0, 8) + "-" + u.slice(8, 12) + "-" + u.slice(12, 16) +
                "-" + u.slice(16, 20) + "-" + u.slice(20, 32);

            return { udid: udidUuid, auth_key: authHex };
        } catch (e) {
            return null;
        }
    }

    /**
     * Process a complete HTTP request reassembled from TLS write chunks.
     * Extracts endpoint, headers (ViewerID, APP-VER, RES-VER), and credentials.
     */
    function _processReassembledRequest(httpText) {
        if (httpText.indexOf("/umamusume/") < 0) return;

        var endpointMatch = httpText.match(/POST\s+\/umamusume\/([^\s]+)\s+HTTP/i);
        var viewerIdMatch = httpText.match(/(?:^|\r\n)(?:ViewerID|ViewerId):\s*(\d+)/i);
        var appVerMatch = httpText.match(/(?:^|\r\n)APP-VER:\s*([^\r\n]+)/i);
        var resVerMatch = httpText.match(/(?:^|\r\n)RES-VER:\s*([^\r\n]+)/i);
        var bodyIdx = httpText.indexOf("\r\n\r\n");
        if (!endpointMatch || bodyIdx < 0) return;

        var endpoint = endpointMatch[1];
        var viewerId = viewerIdMatch ? viewerIdMatch[1] : null;
        var appVer = appVerMatch ? appVerMatch[1].trim() : "";
        var resVer = resVerMatch ? resVerMatch[1].trim() : "";
        var body = httpText.substring(bodyIdx + 4);

        // Try credential extraction from the request body
        var creds = null;
        if (body.length > 100) {
            creds = _extractCredsFromBody(body);
        }

        var record = {
            _seq: _seq++,
            event: "ssl_write_reassembled",
            direction: "out",
            endpoint: endpoint,
            bytes: httpText.length,
        };
        if (viewerId) record.viewerId = viewerId;
        if (appVer) record.appVer = appVer;
        if (resVer) record.resVer = resVer;

        if (creds) {
            record.crypto = {
                udid: creds.udid,
                auth_key: creds.auth_key,
                source: "ssl_layer",
            };
            // Update global crypto state as fallback for Layer 0
            if (!_lastUdidHex) {
                _lastUdidHex = creds.udid.replace(/-/g, "");
            }
        }

        send({ type: "collect", domain: "network", data: record });
    }

    /**
     * Feed a TLS write chunk into the per-connection reassembly buffer.
     * Emits complete HTTP requests when Content-Length is satisfied.
     */
    function _feedSslWriteChunk(connKey, chunk) {
        var buf = (_sslWriteBuffers[connKey] || "") + chunk;
        // Safety cap: discard if buffer grows too large (2MB)
        if (buf.length > 2097152) buf = buf.substring(buf.length - 1048576);

        var start = buf.indexOf("POST ");
        if (start < 0) {
            // No request start found — keep tail for future reassembly
            _sslWriteBuffers[connKey] = buf.slice(-4096);
            return;
        }
        if (start > 0) buf = buf.substring(start);

        var headerEnd = buf.indexOf("\r\n\r\n");
        if (headerEnd < 0) {
            // Headers not yet complete
            _sslWriteBuffers[connKey] = buf;
            return;
        }

        var headers = buf.substring(0, headerEnd);
        var lengthMatch = headers.match(/Content-Length:\s*(\d+)/i);
        var contentLength = lengthMatch ? parseInt(lengthMatch[1], 10) : 0;
        var totalLen = headerEnd + 4 + contentLength;

        if (contentLength > 0 && buf.length < totalLen) {
            // Body not yet complete — wait for more chunks
            _sslWriteBuffers[connKey] = buf;
            return;
        }

        // Complete request assembled — process it
        var completeRequest = contentLength > 0 ? buf.substring(0, totalLen) : buf;
        _processReassembledRequest(completeRequest);

        // Keep remainder for next request
        _sslWriteBuffers[connKey] = buf.length > totalLen ? buf.substring(totalLen) : "";
    }

    const SSL_EXPORT_NAMES = {
        read: ["SSL_read", "SSL_read_ex"],
        write: ["SSL_write", "SSL_write_ex"],
    };

    // Modules that commonly contain the SSL implementation in Unity games
    const SSL_MODULE_HINTS = [
        "libssl",
        "ssleay32",
        "libcrypto",
        "GameAssembly", // BoringSSL sometimes statically linked
        "libil2cpp", // Linux
        "UnityFramework", // macOS/iOS
        "libcurl", // curl backend
    ];

    function tryFindExport(name) {
        // Try well-known modules first
        for (const hint of SSL_MODULE_HINTS) {
            try {
                const mod =
                    Process.getModuleByName(hint + ".dll") ||
                    Process.getModuleByName(hint + ".so") ||
                    Process.getModuleByName(hint + ".dylib") ||
                    Process.getModuleByName(hint);
                if (!mod) continue;
                const addr = mod.findExportByName(name);
                if (addr) {
                    console.log("[network] Found " + name + " in " + mod.name);
                    return addr;
                }
            } catch (e) {}
        }

        // Fallback: search all modules
        try {
            const addr = Module.findExportByName(null, name);
            if (addr) {
                console.log("[network] Found " + name + " (global search)");
                return addr;
            }
        } catch (e) {}

        return null;
    }

    // ── SSL_read: capture server → game (response) data ───────────────

    var sslReadAddr = null;
    for (const name of SSL_EXPORT_NAMES.read) {
        sslReadAddr = tryFindExport(name);
        if (sslReadAddr) break;
    }

    if (sslReadAddr) {
        try {
            Interceptor.attach(sslReadAddr, {
                onEnter: function (args) {
                    this.ssl = args[0];
                    this.buf = args[1];
                    this.num = args[2].toInt32();
                },
                onLeave: function (retval) {
                    var bytesRead = retval.toInt32();
                    if (bytesRead <= 0) return;

                    // Cap at 256KB to capture full race responses
                    var captureLen = Math.min(bytesRead, 262144);
                    try {
                        var data = this.buf.readByteArray(captureLen);
                        send(
                            {
                                type: "collect",
                                domain: "network",
                                data: {
                                    _seq: _seq++,
                                    event: "ssl_read",
                                    direction: "in",
                                    bytes: bytesRead,
                                    captured: captureLen,
                                    truncated: bytesRead > captureLen,
                                },
                            },
                            data,
                        );
                    } catch (e) {}
                },
            });
            hookCount++;
            console.log("[network] Hooked SSL_read");
        } catch (e) {
            console.log("[network] Failed to hook SSL_read: " + e);
        }
    } else {
        console.log("[network] SSL_read not found — trying alternative TLS hooks...");

        // Windows fallback: Schannel (DecryptMessage / EncryptMessage)
        try {
            var secur32 = Process.getModuleByName("secur32.dll");
            if (secur32) {
                var decryptMsg = secur32.findExportByName("DecryptMessage");
                if (decryptMsg) {
                    Interceptor.attach(decryptMsg, {
                        onEnter: function (args) {
                            this.ctxt = args[0];
                            this.msg = args[1];
                        },
                        onLeave: function (retval) {
                            if (retval.toInt32() !== 0) return; // SEC_E_OK = 0
                            // Try to read the first buffer from the SecBufferDesc
                            try {
                                var bufDesc = this.msg;
                                var cBuffers = bufDesc.add(4).readU32();
                                var pBuffers = bufDesc.add(8).readPointer();
                                // Each SecBuffer is 12 bytes (cbBuffer:4, BufferType:4, pvBuffer:ptr)
                                // On 64-bit the struct is padded, so use: 4 + 4 + ptrSize
                                var secBufSize = 4 + 4 + Process.pointerSize;
                                for (var i = 0; i < cBuffers && i < 4; i++) {
                                    var bufEntry = pBuffers.add(i * secBufSize);
                                    var cbBuffer = bufEntry.readU32();
                                    var bufType = bufEntry.add(4).readU32();
                                    // SECBUFFER_DATA = 1
                                    if (bufType === 1 && cbBuffer > 0 && cbBuffer < 65536) {
                                        var pvBuffer = bufEntry.add(8).readPointer();
                                        var captureLen = Math.min(cbBuffer, 32768);
                                        var data = pvBuffer.readByteArray(captureLen);
                                        send(
                                            {
                                                type: "collect",
                                                domain: "network",
                                                data: {
                                                    _seq: _seq++,
                                                    event: "schannel_decrypt",
                                                    direction: "in",
                                                    bytes: cbBuffer,
                                                    captured: captureLen,
                                                    truncated: cbBuffer > captureLen,
                                                },
                                            },
                                            data,
                                        );
                                        break;
                                    }
                                }
                            } catch (e) {}
                        },
                    });
                    hookCount++;
                    console.log("[network] Hooked Schannel DecryptMessage (fallback)");
                }
            }
        } catch (e) {
            // Not on Windows or secur32 not available
        }
    }

    // ── SSL_write: capture game → server (request) data ───────────────

    var sslWriteAddr = null;
    for (const name of SSL_EXPORT_NAMES.write) {
        sslWriteAddr = tryFindExport(name);
        if (sslWriteAddr) break;
    }

    if (sslWriteAddr) {
        try {
            Interceptor.attach(sslWriteAddr, {
                onEnter: function (args) {
                    var ssl = args[0];
                    var buf = args[1];
                    var num = args[2].toInt32();
                    if (num <= 0) return;

                    var captureLen = Math.min(num, 262144);
                    try {
                        var data = buf.readByteArray(captureLen);

                        // Try to extract HTTP method/path from the first bytes
                        var httpMethod = null;
                        var httpUrl = null;
                        var chunkStr = null;
                        try {
                            chunkStr = buf.readUtf8String(Math.min(num, num));
                            if (chunkStr) {
                                var m = chunkStr.match(/^(POST|GET|PUT|DELETE|PATCH)\s+([^\s]+)/);
                                if (m) {
                                    httpMethod = m[1];
                                    httpUrl = m[2];
                                }
                            }
                        } catch (e) {}

                        // Feed into chunk reassembly for complete HTTP request processing
                        if (chunkStr) {
                            var connKey = ssl.toString();
                            _feedSslWriteChunk(connKey, chunkStr);
                        }

                        var record = {
                            _seq: _seq++,
                            event: "ssl_write",
                            direction: "out",
                            bytes: num,
                            captured: captureLen,
                            truncated: num > captureLen,
                        };
                        if (httpMethod) record.httpMethod = httpMethod;
                        if (httpUrl) record.httpUrl = httpUrl;

                        send(
                            {
                                type: "collect",
                                domain: "network",
                                data: record,
                            },
                            data,
                        );
                    } catch (e) {}
                },
            });
            hookCount++;
            console.log("[network] Hooked SSL_write (with chunk reassembly)");
        } catch (e) {
            console.log("[network] Failed to hook SSL_write: " + e);
        }
    } else {
        // Windows fallback: Schannel EncryptMessage
        try {
            var secur32w = Process.getModuleByName("secur32.dll");
            if (secur32w) {
                var encryptMsg = secur32w.findExportByName("EncryptMessage");
                if (encryptMsg) {
                    Interceptor.attach(encryptMsg, {
                        onEnter: function (args) {
                            // Capture the plaintext buffer before encryption
                            try {
                                var bufDesc = args[1];
                                var cBuffers = bufDesc.add(4).readU32();
                                var pBuffers = bufDesc.add(8).readPointer();
                                var secBufSize = 4 + 4 + Process.pointerSize;
                                for (var i = 0; i < cBuffers && i < 4; i++) {
                                    var bufEntry = pBuffers.add(i * secBufSize);
                                    var cbBuffer = bufEntry.readU32();
                                    var bufType = bufEntry.add(4).readU32();
                                    // SECBUFFER_DATA = 1
                                    if (bufType === 1 && cbBuffer > 0 && cbBuffer < 65536) {
                                        var pvBuffer = bufEntry.add(8).readPointer();
                                        var captureLen = Math.min(cbBuffer, 32768);
                                        var data = pvBuffer.readByteArray(captureLen);
                                        send(
                                            {
                                                type: "collect",
                                                domain: "network",
                                                data: {
                                                    _seq: _seq++,
                                                    event: "schannel_encrypt",
                                                    direction: "out",
                                                    bytes: cbBuffer,
                                                    captured: captureLen,
                                                    truncated: cbBuffer > captureLen,
                                                },
                                            },
                                            data,
                                        );
                                        break;
                                    }
                                }
                            } catch (e) {}
                        },
                    });
                    hookCount++;
                    console.log("[network] Hooked Schannel EncryptMessage (fallback)");
                }
            }
        } catch (e) {}
    }

    // ── UnityTLS vtable hooking (fallback) ────────────────────────────
    // When SSL exports aren't found, we can hook TLS write functions
    // directly from Unity's internal TLS interface vtable. The game calls
    // il2cpp_unity_install_unitytls_interface to install a vtable pointer.
    // We read that global, then hook the write function pointers at known
    // offsets (0xd0, 0xd8, 0xe0, 0xe8) which correspond to the TLS send
    // path. This is more resilient than export searching for Unity games.

    if (!sslWriteAddr && !sslReadAddr) {
        (function tryUnityTlsVtable() {
            var ga = null;
            try { ga = Process.findModuleByName("GameAssembly.dll"); } catch (e) {}
            if (!ga) try { ga = Process.findModuleByName("libil2cpp.so"); } catch (e) {}
            if (!ga) return;

            var installFn = ga.findExportByName("il2cpp_unity_install_unitytls_interface");
            if (!installFn) return;

            // Read the function prologue to find the global vtable pointer
            var rb = new Uint8Array(installFn.readByteArray(16));
            var realFn = installFn;

            // Follow relative jump if present (e9 xx xx xx xx)
            if (rb[0] === 0xe9) {
                var off = rb[1] | (rb[2] << 8) | (rb[3] << 16) | (rb[4] << 24);
                if (off > 0x7fffffff) off -= 0x100000000;
                realFn = installFn.add(5 + off);
                rb = new Uint8Array(realFn.readByteArray(16));
            }

            // Look for: mov [rip+disp], rcx (48 89 0d xx xx xx xx)
            var globalPtr = null;
            if (rb[0] === 0x48 && rb[1] === 0x89 && rb[2] === 0x0d) {
                var disp = rb[3] | (rb[4] << 8) | (rb[5] << 16) | (rb[6] << 24);
                if (disp > 0x7fffffff) disp -= 0x100000000;
                globalPtr = realFn.add(7 + disp);
            }
            if (!globalPtr) return;

            var iface = globalPtr.readPointer();
            if (!iface || iface.isNull()) return;

            // Hook the TLS write functions at known vtable offsets
            var unityTlsHooked = 0;
            var vtableAttached = Object.create(null);
            var writeOffsets = [0xd0, 0xd8, 0xe0, 0xe8];

            writeOffsets.forEach(function (off) {
                var addr = iface.add(off).readPointer();
                if (!addr || addr.isNull()) return;
                var key = "utls_" + addr.toString();
                if (vtableAttached[key]) return;
                try {
                    Interceptor.attach(addr, {
                        onEnter: function (args) {
                            var len = args[2].toInt32();
                            if (len <= 0 || len > 1048576 || args[1].isNull()) return;
                            try {
                                var bytes = args[1].readByteArray(len);
                                var u8 = new Uint8Array(bytes);
                                var s = "";
                                for (var i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);

                                // Feed into chunk reassembly
                                _feedSslWriteChunk(args[0].toString(), s);

                                // Also emit raw event
                                send(
                                    {
                                        type: "collect",
                                        domain: "network",
                                        data: {
                                            _seq: _seq++,
                                            event: "unitytls_write",
                                            direction: "out",
                                            bytes: len,
                                            captured: len,
                                            truncated: false,
                                        },
                                    },
                                    bytes,
                                );
                            } catch (e) {}
                        },
                    });
                    vtableAttached[key] = true;
                    unityTlsHooked++;
                } catch (e) {}
            });

            if (unityTlsHooked > 0) {
                hookCount += unityTlsHooked;
                console.log(
                    "[network] Hooked " + unityTlsHooked +
                    " UnityTLS vtable write functions (fallback)",
                );
            }
        })();
    }

    // ══════════════════════════════════════════════════════════════════
    // LAYER 2: MsgPack Formatter hooks (il2cpp)
    // ══════════════════════════════════════════════════════════════════
    //
    // The game has Gallop.MsgPack.Formatters.*Formatter classes, each with
    // Serialize and Deserialize methods. Hooking these tells us the *name*
    // of every API request/response object being serialised.

    console.log("[network] Scanning for MsgPack Formatter classes...");

    var formatterClasses = {};

    iterAssemblyClasses(function (classPtr, fullName, ns, name) {
        // Match Gallop.MsgPack.Formatters.*Formatter
        if (fullName.indexOf("Gallop.MsgPack.Formatters.") !== 0) return;
        if (!fullName.endsWith("Formatter")) return;

        // Extract the meaningful name (strip namespace + "Formatter" suffix)
        var shortName = fullName.replace("Gallop.MsgPack.Formatters.", "").replace("Formatter", "");
        formatterClasses[fullName] = {
            classPtr: classPtr,
            shortName: shortName,
        };
    });

    var formatterCount = Object.keys(formatterClasses).length;
    console.log("[network] Found " + formatterCount + " MsgPack Formatter classes.");

    // Hook Serialize and Deserialize on each formatter
    var formatterHooks = 0;
    var MAX_FORMATTER_HOOKS = 300; // safety cap

    // Note: Request/Response class lookup is handled by Layer 3's
    // dataClassPtrs / getDataClassInfo. Formatters use the same cache.

    function getReqRespFields(formatterShortName) {
        // formatterShortName is e.g. "Gallop_SingleModeFreeChoiceRewardRequest"
        // Convert to "Gallop.SingleModeFreeChoiceRewardRequest"
        var className = formatterShortName.replace(/_/g, ".");
        // Reuse Layer 3's data class lookup (populated later during setup,
        // but formatter hooks fire at runtime after setup completes)
        var info = getDataClassInfo(className);
        return info ? info.fieldList : null;
    }

    for (var fqn in formatterClasses) {
        if (formatterHooks >= MAX_FORMATTER_HOOKS) break;

        (function (fqn) {
            var entry = formatterClasses[fqn];
            var info = extractClassInfo(entry.classPtr, fqn);
            var sName = entry.shortName;

            // Hook Serialize — reads the value being serialized (request data)
            if (info.methods["Serialize"]) {
                if (
                    hookMethod(info, "Serialize", -1, {
                        onEnter: function (args) {
                            // args: [this, ref writer, value, options]
                            // For instance methods, args[0]=this, args[1]=writer,
                            // args[2]=value (the request/response object), args[3]=options
                            var record = {
                                event: "msgpack_serialize",
                                _seq: _seq++,
                                direction: "out",
                                formatter: sName,
                            };

                            // Try to read fields from the value object
                            try {
                                var valuePtr = args[2];
                                if (valuePtr && !valuePtr.isNull()) {
                                    var fields = getReqRespFields(sName);
                                    if (fields) {
                                        var data = readObjectFields(valuePtr, fields);
                                        if (data) record.fields = data;
                                    }
                                }
                            } catch (e) {}

                            send({
                                type: "collect",
                                domain: "network",
                                data: record,
                            });
                        },
                    })
                ) {
                    formatterHooks++;
                }
            }

            // Hook Deserialize — reads the return value (response data)
            if (info.methods["Deserialize"]) {
                if (
                    hookMethod(info, "Deserialize", -1, {
                        onEnter: function (args) {
                            this._formatterName = sName;
                        },
                        onLeave: function (retval) {
                            var record = {
                                event: "msgpack_deserialize",
                                _seq: _seq++,
                                direction: "in",
                                formatter: this._formatterName,
                            };

                            // Try to read fields from the return value
                            try {
                                if (retval && !retval.isNull()) {
                                    var fields = getReqRespFields(this._formatterName);
                                    if (fields) {
                                        var data = readObjectFields(retval, fields);
                                        if (data) record.fields = data;
                                    }
                                }
                            } catch (e) {}

                            send({
                                type: "collect",
                                domain: "network",
                                data: record,
                            });
                        },
                    })
                ) {
                    formatterHooks++;
                }
            }
        })(fqn);
    }

    hookCount += formatterHooks;
    console.log("[network] " + formatterHooks + " MsgPack Formatter hooks installed.");

    // ══════════════════════════════════════════════════════════════════
    // LAYER 3: Gallop.*Task API hooks (il2cpp)
    // ══════════════════════════════════════════════════════════════════
    //
    // Every API call in the game is a `Gallop.*Task` class, e.g.
    //   Gallop.SingleModeCheckEventTask
    //   Gallop.SingleModeExecCommandTask
    // They all share the same field layout:
    //   offset 16: postData (byte[])
    //   offset 24: onSuccess callback
    //   offset 32: onError callback
    //   offset 40: headers dict
    //   offset 48: request (Cute.Http.IWebRequest)
    //
    // We scan for ALL Gallop.*Task classes and hook Send + Deserialize
    // on each one. When Send fires, `this` IS the task, so we can read
    // the class name and postData directly.
    //
    // IMPORTANT: Send, Deserialize, and OnError are base-class methods
    // shared across ALL ~300 Task subclasses (same compiled address).
    // hookMethod deduplicates — only ONE callback is installed.
    // We use readClassName(self) at runtime to determine the concrete
    // type, then look up the matching Request/Response class to read
    // its fields dynamically.

    console.log("[network] Scanning for Gallop API Task classes...");

    // Helper: read the il2cpp class name from an object pointer
    function readClassName(objPtr) {
        try {
            var klass = objPtr.readPointer();
            if (klass.isNull()) return null;
            var n = readCStr(fn.class_get_name(klass));
            var ns = readCStr(fn.class_get_namespace(klass));
            return ns ? ns + "." + n : n;
        } catch (e) {
            return null;
        }
    }

    // Helper: read il2cpp array length
    function readArrayLength(arrPtr) {
        if (!arrPtr || arrPtr.isNull()) return -1;
        try {
            var lenOffset = ptrSize === 8 ? 24 : 12;
            return arrPtr.add(lenOffset).readS32();
        } catch (e) {
            return -1;
        }
    }

    // Helper: derive API short name from a task class name
    function taskToApiName(taskClassName) {
        return taskClassName.replace("Gallop.", "").replace(/Task$/, "");
    }

    // ── Step 1: Pre-scan Request/Response data classes ────────────────
    //
    // Each API has matching Gallop.*Request and Gallop.*Response classes
    // with actual data fields (story_id, choice_number, stat changes etc.)
    // We extract their field lists so we can read Response objects after
    // Deserialize returns them, and Request objects if we find them.

    console.log("[network] Scanning for Request/Response data classes...");

    var dataClassPtrs = Object.create(null); // className → classPtr

    iterAssemblyClasses(function (classPtr, fullName, ns, name) {
        if (ns !== "Gallop") return;
        if (name.endsWith("Request") || name.endsWith("Response")) {
            dataClassPtrs[fullName] = classPtr;
        }
    });

    // Extract field info for each Request/Response class
    var dataClassInfoCache = Object.create(null); // className → classInfo

    function getDataClassInfo(className) {
        if (className in dataClassInfoCache) return dataClassInfoCache[className];
        var cp = dataClassPtrs[className];
        if (!cp) {
            dataClassInfoCache[className] = null;
            return null;
        }
        var info = extractClassInfoWithParents(cp, className);
        dataClassInfoCache[className] = info;
        return info;
    }

    // Cache for task class info extracted at runtime (keyed by class name)
    var taskClassInfoCache = Object.create(null);

    function getTaskClassInfo(objPtr, className) {
        if (className in taskClassInfoCache) return taskClassInfoCache[className];
        try {
            var klass = objPtr.readPointer();
            if (!klass || klass.isNull()) return null;
            var info = extractClassInfoWithParents(klass, className);
            taskClassInfoCache[className] = info;
            return info;
        } catch (e) {
            taskClassInfoCache[className] = null;
            return null;
        }
    }

    console.log(
        "[network] Found " + Object.keys(dataClassPtrs).length + " Request/Response data classes.",
    );

    // ── Step 2: Scan Task classes ─────────────────────────────────────

    var taskClasses = {};

    iterAssemblyClasses(function (classPtr, fullName, ns, name) {
        // Match Gallop.*Task classes (the API call wrappers)
        if (ns !== "Gallop") return;
        if (!name.endsWith("Task")) return;
        // Skip obvious non-API classes
        if (name.indexOf("UniTask") !== -1) return;
        if (name.indexOf("Coroutine") !== -1) return;
        taskClasses[fullName] = classPtr;
    });

    var taskCount = Object.keys(taskClasses).length;
    console.log("[network] Found " + taskCount + " Gallop.*Task classes.");

    // ── Step 3: Install hooks ─────────────────────────────────────────
    //
    // Because Send/Deserialize/OnError are inherited base-class methods,
    // hookMethod will only succeed for the FIRST task (dedup).
    // The callbacks must NOT rely on closure-captured task-specific vars —
    // they resolve everything dynamically via readClassName(self).

    var taskHooks = 0;
    var MAX_TASK_HOOKS = 600;

    for (var taskFqn in taskClasses) {
        if (taskHooks >= MAX_TASK_HOOKS) break;

        (function (fullName) {
            var classPtr = taskClasses[fullName];
            var info = extractClassInfo(classPtr, fullName);

            // Hook Send — fires when the game sends this API request
            if (info.methods["Send"]) {
                if (
                    hookMethod(info, "Send", -1, {
                        onEnter: function (args) {
                            var self = args[0];
                            var taskName = readClassName(self) || "UnknownTask";
                            var apiName = taskToApiName(taskName);

                            // Read postData byte[] at offset 16
                            var postDataSize = -1;
                            var postDataBuf = null;
                            try {
                                var arrPtr = self.add(16).readPointer();
                                if (arrPtr && !arrPtr.isNull()) {
                                    postDataSize = readArrayLength(arrPtr);
                                    if (postDataSize > 0 && postDataSize <= 1048576) {
                                        postDataBuf = readIl2cppByteArray(arrPtr, 262144);
                                        if (!postDataBuf) {
                                            console.log(
                                                "[network] WARN: readIl2cppByteArray returned null for " +
                                                    apiName +
                                                    " (len=" +
                                                    postDataSize +
                                                    ", arrPtr=" +
                                                    arrPtr +
                                                    ")",
                                            );
                                        }
                                    }
                                }
                            } catch (e) {
                                console.log(
                                    "[network] ERROR reading postData for " + apiName + ": " + e,
                                );
                            }

                            var record = {
                                event: "api_send",
                                _seq: _seq++,
                                _reqId: ++_nextReqId,
                                direction: "out",
                                task: taskName,
                                api: apiName,
                                postDataBytes: postDataSize,
                            };

                            // Track for pairing with the response
                            _pendingReqIds[apiName] = record._reqId;

                            send(
                                {
                                    type: "collect",
                                    domain: "network",
                                    data: record,
                                },
                                postDataBuf,
                            );
                        },
                    })
                ) {
                    taskHooks++;
                }
            }

            // Hook Deserialize — fires when the response is parsed.
            // retval is the deserialized Response object.
            // args[1] may be the raw response byte[] or a MessagePackReader.
            if (info.methods["Deserialize"]) {
                if (
                    hookMethod(info, "Deserialize", -1, {
                        onEnter: function (args) {
                            this._self = args[0];
                            this._taskName = readClassName(args[0]) || "UnknownTask";
                            this._apiName = taskToApiName(this._taskName);

                            // Try to capture raw response bytes from args[1]
                            // (byte[] parameter to Deserialize)
                            this._rawBuf = null;
                            try {
                                var rawArg = args[1];
                                if (rawArg && !rawArg.isNull()) {
                                    // Check if it looks like an il2cpp array
                                    var len = readArrayLength(rawArg);
                                    if (len > 0 && len < 1048576) {
                                        this._rawBuf = readIl2cppByteArray(rawArg, 262144);
                                    }
                                }
                            } catch (e) {}
                        },
                        onLeave: function (retval) {
                            // Pop the pending request ID for this API
                            var pairedReqId = _pendingReqIds[this._apiName] || null;
                            if (pairedReqId !== null) {
                                delete _pendingReqIds[this._apiName];
                            }

                            var record = {
                                event: "api_response",
                                _seq: _seq++,
                                _reqId: pairedReqId,
                                direction: "in",
                                task: this._taskName,
                                api: this._apiName,
                            };

                            // ── Read Response object fields from retval ──
                            // Deserialize returns the typed Response object
                            // (e.g. SingleModeFreeCheckEventResponse).
                            // Look up its class info and read all primitive fields.
                            try {
                                if (retval && !retval.isNull()) {
                                    // Get the actual Response class name from retval's klass
                                    var retClassName = readClassName(retval);
                                    if (retClassName) {
                                        record.responseClass = retClassName;
                                        var respInfo = getDataClassInfo(retClassName);
                                        if (!respInfo) {
                                            // Fallback: extract fields on the fly via IL2CPP reflection
                                            try {
                                                var retKlass = retval.readPointer();
                                                if (!retKlass.isNull()) {
                                                    respInfo = extractClassInfoWithParents(
                                                        retKlass,
                                                        retClassName,
                                                    );
                                                }
                                            } catch (e) {}
                                        }
                                        if (respInfo && respInfo.fieldList.length > 0) {
                                            var fields = readObjectFields(
                                                retval,
                                                respInfo.fieldList,
                                            );
                                            if (fields) record.responseFields = fields;
                                        }
                                    }
                                }
                            } catch (e) {
                                console.log(
                                    "[network] WARN: failed reading retval for " +
                                        this._apiName +
                                        ": " +
                                        e,
                                );
                            }

                            // ── Also try reading task object fields after Deserialize ──
                            // Task classes end in "Task" not "Request"/"Response",
                            // so they're not in dataClassPtrs. Extract live (cached).
                            try {
                                if (this._self && !this._self.isNull()) {
                                    var taskInfo = getTaskClassInfo(this._self, this._taskName);
                                    if (taskInfo && taskInfo.fieldList.length > 0) {
                                        var tFields = readObjectFields(
                                            this._self,
                                            taskInfo.fieldList,
                                        );
                                        if (tFields) record.taskFields = tFields;
                                    }
                                }
                            } catch (e) {}

                            send(
                                {
                                    type: "collect",
                                    domain: "network",
                                    data: record,
                                },
                                this._rawBuf || null,
                            );
                        },
                    })
                ) {
                    taskHooks++;
                }
            }

            // Hook OnError
            if (info.methods["OnError"]) {
                if (
                    hookMethod(info, "OnError", -1, {
                        onEnter: function (args) {
                            var self = args[0];
                            var taskName = readClassName(self) || "UnknownTask";

                            send({
                                type: "collect",
                                domain: "network",
                                data: {
                                    event: "api_error",
                                    _seq: _seq++,
                                    direction: "in",
                                    task: taskName,
                                    api: taskToApiName(taskName),
                                },
                            });
                        },
                    })
                ) {
                    taskHooks++;
                }
            }
        })(taskFqn);
    }

    hookCount += taskHooks;
    console.log("[network] " + taskHooks + " Gallop Task hooks installed.");

    // ── Summary ───────────────────────────────────────────────────────

    console.log("[network] Total: " + hookCount + " network hooks installed.");
    send({ type: "hook_status", module: "network", hookCount: hookCount });
})();
