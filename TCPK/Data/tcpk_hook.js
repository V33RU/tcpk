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

// Winsock (Windows): send(s, buf, len, flags) / recv(s, buf, len, flags)
hookSend('ws2_32.dll', 'send', 1, 2);
hookRecv('ws2_32.dll', 'recv', 1);
// OpenSSL (bundled apps, and Linux): SSL_write(ssl, buf, num) / SSL_read(ssl, buf, num).
// null module = search every loaded module.
hookSend(null, 'SSL_write', 1, 2);
hookRecv(null, 'SSL_read', 1);
// libc / generic (Linux; also a fallback): send / recv / write
hookSend(null, 'send', 1, 2);
hookRecv(null, 'recv', 1);
hookSend(null, 'write', 1, 2);

emit({ dir: 'meta', func: 'init', len: 0, data: 'tcpk hook installed' });
