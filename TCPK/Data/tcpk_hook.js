// TCPK Frida hook - inline API interception (the Echo Mirage approach). Reads plaintext
// at the socket / TLS API, so it works regardless of proxy, CA trust, certificate pinning
// or protocol. READ-ONLY: it observes buffers, it never modifies a request or response.
// Emits one line per capture as: TCPKHOOK <json>. TCPK (ConvertFrom-TcpkHookCapture)
// parses those lines into intercept.* findings.
'use strict';

function emit(rec) {
    try { console.log('TCPKHOOK ' + JSON.stringify(rec)); } catch (e) { }
}

// Read up to `len` bytes at `ptr` as a byte-preserving latin1 string (capped).
function readText(ptr, len) {
    try {
        if (ptr.isNull() || len <= 0) { return ''; }
        var n = Math.min(len, 8192);
        var u8 = new Uint8Array(ptr.readByteArray(n));
        var s = '';
        for (var i = 0; i < u8.length; i++) { s += String.fromCharCode(u8[i]); }
        return s;
    } catch (e) { return ''; }
}

// Resolve an exported function address across frida versions (the Module.* API changed
// between 16 and 17). mod = null searches every loaded module.
function resolveExport(mod, name) {
    try { if (typeof Module.findExportByName === 'function') { var a = Module.findExportByName(mod, name); if (a) { return a; } } } catch (e) { }
    try { if (typeof Module.getExportByName === 'function') { return Module.getExportByName(mod, name); } } catch (e) { }
    try { if (mod === null && typeof Module.getGlobalExportByName === 'function') { return Module.getGlobalExportByName(name); } } catch (e) { }
    try {
        if (mod) {
            var m = Process.getModuleByName(mod);
            if (m && typeof m.getExportByName === 'function') { return m.getExportByName(name); }
            if (m && typeof m.findExportByName === 'function') { return m.findExportByName(name); }
        } else {
            var mods = Process.enumerateModules();
            for (var i = 0; i < mods.length; i++) {
                try {
                    var e2 = (typeof mods[i].findExportByName === 'function') ? mods[i].findExportByName(name)
                           : (typeof mods[i].getExportByName === 'function') ? mods[i].getExportByName(name) : null;
                    if (e2) { return e2; }
                } catch (e) { }
            }
        }
    } catch (e) { }
    return null;
}

// Send-direction: buffer + length are available on entry (idxBuf, idxLen are arg indexes).
function hookSend(mod, name, idxBuf, idxLen) {
    var addr = resolveExport(mod, name);
    if (!addr) { return; }
    try {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                var t = readText(args[idxBuf], args[idxLen].toInt32());
                if (t) { emit({ dir: 'send', func: name, len: t.length, data: t }); }
            }
        });
    } catch (e) { }
}

// Recv-direction: the buffer is filled by the call; the byte count is the return value.
function hookRecv(mod, name, idxBuf) {
    var addr = resolveExport(mod, name);
    if (!addr) { return; }
    try {
        Interceptor.attach(addr, {
            onEnter: function (args) { this.buf = args[idxBuf]; },
            onLeave: function (retval) {
                var n = retval.toInt32();
                if (n > 0 && this.buf) {
                    var t = readText(this.buf, n);
                    if (t) { emit({ dir: 'recv', func: name, len: t.length, data: t }); }
                }
            }
        });
    } catch (e) { }
}

// Recv-direction where the byte count is written to *lpdwRead (a DWORD*), read on return
// and only when the call succeeded (retval != 0). Used by WinHttpReadData / InternetReadFile,
// whose ReadData APIs report the length through an out-parameter, not the return value.
function hookRecvOutLen(mod, name, idxBuf, idxOutLen) {
    var addr = resolveExport(mod, name);
    if (!addr) { return; }
    try {
        Interceptor.attach(addr, {
            onEnter: function (args) { this.buf = args[idxBuf]; this.pLen = args[idxOutLen]; },
            onLeave: function (retval) {
                try {
                    if (retval.toInt32() === 0) { return; }          // FALSE -> failed read
                    if (!this.buf || !this.pLen || this.pLen.isNull()) { return; }
                    var n = this.pLen.readU32();
                    if (n > 0) { var t = readText(this.buf, n); if (t) { emit({ dir: 'recv', func: name, len: t.length, data: t }); } }
                } catch (e) { }
            }
        });
    } catch (e) { }
}

// SChannel (secur32/sspicli) SecBufferDesc walker. EncryptMessage/DecryptMessage pass a
// PSecBufferDesc; the PLAINTEXT lives in the SECBUFFER_DATA (type 1) buffer -- present
// BEFORE the call for encrypt, filled AFTER the call for decrypt. This is where TLS
// plaintext is recoverable for native (non-.NET, non-OpenSSL) Windows apps. x64 layouts:
// SecBufferDesc { u32 ulVersion; u32 cBuffers; ptr pBuffers } (pBuffers @ +8);
// SecBuffer { u32 cbBuffer; u32 BufferType; ptr pvBuffer } (16 bytes, pvBuffer @ +8).
function readSecBuffers(pDesc, name, dir) {
    try {
        if (!pDesc || pDesc.isNull()) { return; }
        var cBuffers = pDesc.add(4).readU32();
        var pBuffers = pDesc.add(Process.pointerSize).readPointer();
        if (pBuffers.isNull() || cBuffers <= 0 || cBuffers > 16) { return; }
        for (var i = 0; i < cBuffers; i++) {
            var b = pBuffers.add(i * (8 + Process.pointerSize));
            var cb = b.readU32();
            var type = b.add(4).readU32();
            if (type !== 1) { continue; }                 // SECBUFFER_DATA
            if (cb <= 0 || cb > 1048576) { continue; }
            var pv = b.add(Process.pointerSize).readPointer();
            if (pv.isNull()) { continue; }
            var t = readText(pv, cb);
            if (t) { emit({ dir: dir, func: name, len: t.length, data: t }); }
        }
    } catch (e) { }
}

// idxMsg = argument index of the PSecBufferDesc; decrypt reads it on return (post-decrypt).
function hookSchannel(name, idxMsg, decrypt) {
    var addr = resolveExport('secur32.dll', name);
    if (!addr) { addr = resolveExport('sspicli.dll', name); }
    if (!addr) { return; }
    try {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                this.pMsg = args[idxMsg];
                if (!decrypt) { readSecBuffers(this.pMsg, name, 'send'); }   // plaintext present pre-call
            },
            onLeave: function (retval) {
                if (decrypt) { readSecBuffers(this.pMsg, name, 'recv'); }     // plaintext filled post-call
            }
        });
    } catch (e) { }
}

// Winsock (Windows): send(s, buf, len, flags) / recv(s, buf, len, flags)
hookSend('ws2_32.dll', 'send', 1, 2);
hookRecv('ws2_32.dll', 'recv', 1);
// Windows SChannel (secur32): EncryptMessage(phCtx, fQOP, pMsg=arg2, seq) plaintext pre-call;
// DecryptMessage(phCtx, pMsg=arg1, seq, pfQOP) plaintext post-call. The native-TLS recovery path.
hookSchannel('EncryptMessage', 2, false);
hookSchannel('DecryptMessage', 1, true);
// WinHTTP: WinHttpWriteData(hReq, buf, len, *written) / WinHttpReadData(hReq, buf, len, *read).
hookSend('winhttp.dll', 'WinHttpWriteData', 1, 2);
hookRecvOutLen('winhttp.dll', 'WinHttpReadData', 1, 3);
// WinINet: HttpSendRequest optional body (arg3/len arg4) + InternetReadFile(hFile, buf, len, *read).
hookSend('wininet.dll', 'HttpSendRequestW', 3, 4);
hookSend('wininet.dll', 'HttpSendRequestA', 3, 4);
hookRecvOutLen('wininet.dll', 'InternetReadFile', 1, 3);
// OpenSSL (bundled apps, and Linux): SSL_write(ssl, buf, num) / SSL_read(ssl, buf, num).
// null module = search every loaded module.
hookSend(null, 'SSL_write', 1, 2);
hookRecv(null, 'SSL_read', 1);
// libc / generic (Linux; also a fallback): send / recv / write
hookSend(null, 'send', 1, 2);
hookRecv(null, 'recv', 1);
hookSend(null, 'write', 1, 2);

emit({ dir: 'meta', func: 'init', len: 0, data: 'tcpk hook installed' });
