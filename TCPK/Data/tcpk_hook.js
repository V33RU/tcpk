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

// ---- Intercept channel (synchronous buffer modification via named pipe) ----------
// When the TCPK GUI starts the pipe server (\\.\pipe\tcpk_intercept), each outbound
// buffer is offered for modification before the send call completes. No server running
// -> falls back to read-only emit with zero overhead (pipe open fails, flag is set once).
// Protocol: write [uint32 len LE][data bytes], read back [uint32 len LE][data bytes].
// Reply len == 0 means drop; any other length means forward (possibly modified) content.

var _iPipe = null;   // null = uninit, ptr(0) = unavailable, handle = connected
var _iWF   = null;   // NativeFunction: WriteFile
var _iRF   = null;   // NativeFunction: ReadFile
var _iPeek = null;   // NativeFunction: PeekNamedPipe

function _iPipeInit() {
    if (_iPipe !== null) { return; }
    try {
        var k32 = 'kernel32.dll';
        var aCFW = Module.findExportByName(k32, 'CreateFileW');
        var aWF  = Module.findExportByName(k32, 'WriteFile');
        var aRF  = Module.findExportByName(k32, 'ReadFile');
        var aPNP = Module.findExportByName(k32, 'PeekNamedPipe');
        if (!aCFW || !aWF || !aRF || !aPNP) { _iPipe = ptr(0); return; }
        _iWF   = new NativeFunction(aWF,  'int', ['pointer','pointer','uint32','pointer','pointer']);
        _iRF   = new NativeFunction(aRF,  'int', ['pointer','pointer','uint32','pointer','pointer']);
        _iPeek = new NativeFunction(aPNP, 'int', ['pointer','pointer','uint32','pointer','pointer','pointer']);
        var CFW = new NativeFunction(aCFW, 'pointer', ['pointer','uint32','uint32','pointer','uint32','uint32','pointer']);
        var INVAL = ptr(Process.pointerSize === 8 ? '0xFFFFFFFFFFFFFFFF' : '0xFFFFFFFF');
        var pn = Memory.allocUtf16String('\\\\.\\pipe\\tcpk_intercept');
        var h  = CFW(pn, 0xC0000000, 0, ptr(0), 3, 0x80, ptr(0));
        _iPipe = (!h.isNull() && !h.equals(INVAL)) ? h : ptr(0);
    } catch (e) { _iPipe = ptr(0); }
}

// Offer a latin1 string to the intercept pipe. Returns null (no pipe / timeout),
// '' (drop), or the modified latin1 string. timeoutMs caps how long the hook blocks.
function _iPipeExchange(text, timeoutMs) {
    _iPipeInit();
    if (_iPipe.isNull() || _iPipe.equals(ptr(0))) { return null; }
    try {
        var bytes = new Uint8Array(text.length);
        for (var i = 0; i < text.length; i++) { bytes[i] = text.charCodeAt(i) & 0xFF; }
        var hdr = Memory.alloc(4); hdr.writeU32(bytes.length);
        var dat = Memory.alloc(bytes.length + 1);
        for (var j = 0; j < bytes.length; j++) { dat.add(j).writeU8(bytes[j]); }
        var pW = Memory.alloc(4);
        if (_iWF(_iPipe, hdr, 4, pW, ptr(0)) === 0) { _iPipe = ptr(0); return null; }
        if (bytes.length > 0 && _iWF(_iPipe, dat, bytes.length, pW, ptr(0)) === 0) { _iPipe = ptr(0); return null; }
        // Poll for reply: 50 ms steps up to timeoutMs
        var pAvail = Memory.alloc(4); var rbuf = Memory.alloc(4); var pR = Memory.alloc(4);
        var polls = Math.ceil(timeoutMs / 50);
        for (var t = 0; t < polls; t++) {
            pAvail.writeU32(0);
            if (_iPeek(_iPipe, ptr(0), 0, ptr(0), pAvail, ptr(0)) && pAvail.readU32() >= 4) {
                _iRF(_iPipe, rbuf, 4, pR, ptr(0));
                var rLen = rbuf.readU32();
                if (rLen === 0) { return ''; }
                var rdat = Memory.alloc(rLen);
                _iRF(_iPipe, rdat, rLen, pR, ptr(0));
                var s = ''; for (var k = 0; k < rLen; k++) { s += String.fromCharCode(rdat.add(k).readU8()); }
                return s;
            }
            Thread.sleep(0.05);
        }
    } catch (e) { _iPipe = ptr(0); }
    return null;  // timeout: pass through
}

// Send-direction: buffer + length are available on entry (idxBuf, idxLen are arg indexes).
// When the intercept pipe is connected, the buffer is offered for modification before
// the call completes; falls back to read-only emit if no pipe server is running.
function hookSend(mod, name, idxBuf, idxLen) {
    var addr = resolveExport(mod, name);
    if (!addr) { return; }
    try {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                var len = args[idxLen].toInt32();
                var t = readText(args[idxBuf], len);
                if (!t) { return; }
                emit({ dir: 'send', func: name, len: t.length, data: t });
                var m = _iPipeExchange(t, 2000);
                if (m === null) { return; }  // no pipe or timeout: pass through unchanged
                if (m.length === 0) {
                    args[idxLen] = ptr(0);
                    emit({ dir: 'intercept', func: name, len: 0, data: '[DROPPED]' });
                } else {
                    var wl = Math.min(m.length, len);
                    for (var i = 0; i < wl; i++) { args[idxBuf].add(i).writeU8(m.charCodeAt(i) & 0xFF); }
                    if (wl < len) { args[idxLen] = ptr(wl); }
                    emit({ dir: 'intercept', func: name, len: wl, data: m.substring(0, wl) });
                }
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

// ---- WSASend / WSARecv (Gap 1 fix: .NET overlapped-I/O coverage) ----------------
// .NET Socket uses WSASend/WSARecv (scatter-gather, overlapped) rather than send/recv.
// WSABUF struct: { ULONG len [4B] + padding [(ptrSize-4)B] + CHAR* buf [ptrSize B] }
// Stride = 2 * pointerSize (8 on x86, 16 on x64).
// WSARecv: only synchronous completions (retval == 0) are captured; WSA_IO_PENDING
// means async I/O -- the filled buffers land via the completion port and are not hooked.

var _WBP = Process.pointerSize;
var _WBS = 2 * _WBP;

function _emitWSABufs(pBufs, nBufs, fname, fdir) {
    try {
        if (!pBufs || pBufs.isNull() || nBufs <= 0 || nBufs > 64) { return; }
        for (var i = 0; i < nBufs; i++) {
            var e = pBufs.add(i * _WBS);
            var blen = e.readU32(); var bptr = e.add(_WBP).readPointer();
            if (blen > 0 && bptr && !bptr.isNull()) {
                var t = readText(bptr, blen); if (t) { emit({ dir: fdir, func: fname, len: t.length, data: t }); }
            }
        }
    } catch (e2) { }
}

// WSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletion)
function hookWSASend() {
    var addr = resolveExport('ws2_32.dll', 'WSASend');
    if (!addr) { return; }
    try {
        Interceptor.attach(addr, {
            onEnter: function (args) { _emitWSABufs(args[1], args[2].toInt32(), 'WSASend', 'send'); }
        });
    } catch (e) { }
}

// WSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletion)
function hookWSARecv() {
    var addr = resolveExport('ws2_32.dll', 'WSARecv');
    if (!addr) { return; }
    try {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                this.pBufs = args[1]; this.nBufs = args[2].toInt32(); this.pGot = args[3];
            },
            onLeave: function (retval) {
                if (retval.toInt32() !== 0) { return; }  // async (WSA_IO_PENDING=997) or error
                try {
                    var got = (this.pGot && !this.pGot.isNull()) ? this.pGot.readU32() : 0;
                    if (got <= 0 || !this.pBufs || this.pBufs.isNull()) { return; }
                    var left = got;
                    for (var i = 0; i < this.nBufs && left > 0; i++) {
                        var e = this.pBufs.add(i * _WBS);
                        var cap = e.readU32(); var buf = e.add(_WBP).readPointer();
                        var n = Math.min(cap, left);
                        if (n > 0 && buf && !buf.isNull()) {
                            var t = readText(buf, n);
                            if (t) { emit({ dir: 'recv', func: 'WSARecv', len: t.length, data: t }); }
                            left -= n;
                        }
                    }
                } catch (e2) { }
            }
        });
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
// Gap 1 fix: WSA scatter-gather (.NET overlapped-I/O coverage)
hookWSASend();
hookWSARecv();

emit({ dir: 'meta', func: 'init', len: 0, data: 'tcpk hook installed' });
