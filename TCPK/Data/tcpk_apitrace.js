// TCPK Frida API tracer - hooks security-relevant Windows APIs in a RUNNING target and logs
// each call (READ-ONLY: it observes arguments, it never modifies a call or return value).
// Emits one line per call as: TCPKTRACE <json>. TCPK (ConvertFrom-TcpkApiTrace) parses those
// lines into api-trace.* findings: weak crypto, process/command launch, secrets written to
// disk or the registry, and DPAPI use. Run with: frida -p <pid> -l tcpk_apitrace.js
'use strict';

function emit(rec) { try { console.log('TCPKTRACE ' + JSON.stringify(rec)); } catch (e) { } }

// Resolve an export across the Frida 16/17 Module API differences (as tcpk_hook.js does).
function resolveExport(mod, name) {
    try { if (typeof Module.findExportByName === 'function') { var a = Module.findExportByName(mod, name); if (a) { return a; } } } catch (e) { }
    try { if (typeof Module.getExportByName === 'function') { return Module.getExportByName(mod, name); } } catch (e) { }
    try { if (mod === null && typeof Module.getGlobalExportByName === 'function') { return Module.getGlobalExportByName(name); } } catch (e) { }
    return null;
}
function hook(mod, name, cb) { try { var a = resolveExport(mod, name); if (a) { Interceptor.attach(a, cb); return true; } } catch (e) { } return false; }
function w(ptr) { try { return (ptr && !ptr.isNull()) ? (ptr.readUtf16String(512) || '') : ''; } catch (e) { return ''; } }
function a(ptr) { try { return (ptr && !ptr.isNull()) ? (ptr.readAnsiString(512) || '') : ''; } catch (e) { return ''; } }
// printable-ASCII preview of a buffer (secrets in cleartext show up here)
function preview(ptr, len) {
    try {
        var n = Math.min(len, 512); if (!ptr || ptr.isNull() || n <= 0) { return ''; }
        var u8 = new Uint8Array(ptr.readByteArray(n)); var s = '';
        for (var i = 0; i < u8.length; i++) { var ch = u8[i]; s += (ch >= 32 && ch < 127) ? String.fromCharCode(ch) : '.'; }
        return s;
    } catch (e) { return ''; }
}

// --- crypto: algorithm names / hash ids (weak alg selection shows up at open/create) ---
hook('bcrypt.dll', 'BCryptOpenAlgorithmProvider', { onEnter: function (args) { var alg = w(args[1]); if (alg) { emit({ cat: 'crypto', api: 'BCryptOpenAlgorithmProvider', alg: alg }); } } });
hook('advapi32.dll', 'CryptCreateHash', { onEnter: function (args) { emit({ cat: 'crypto', api: 'CryptCreateHash', algid: args[1].toInt32() }); } });
hook('advapi32.dll', 'CryptDeriveKey', { onEnter: function (args) { emit({ cat: 'crypto', api: 'CryptDeriveKey', algid: args[1].toInt32() }); } });

// --- process / command launch ---
hook('kernel32.dll', 'CreateProcessW', { onEnter: function (args) { emit({ cat: 'process', api: 'CreateProcessW', app: w(args[0]), cmd: w(args[1]) }); } });
hook('kernel32.dll', 'CreateProcessA', { onEnter: function (args) { emit({ cat: 'process', api: 'CreateProcessA', app: a(args[0]), cmd: a(args[1]) }); } });
hook('kernel32.dll', 'WinExec', { onEnter: function (args) { emit({ cat: 'process', api: 'WinExec', cmd: a(args[0]) }); } });
hook('shell32.dll', 'ShellExecuteW', { onEnter: function (args) { emit({ cat: 'process', api: 'ShellExecuteW', file: w(args[2]), params: w(args[3]) }); } });
hook(null, 'system', { onEnter: function (args) { emit({ cat: 'command', api: 'system', cmd: a(args[0]) }); } });

// --- secrets written to disk / registry ---
hook('kernel32.dll', 'WriteFile', { onEnter: function (args) { try { var n = args[2].toInt32(); if (n > 0) { emit({ cat: 'file', api: 'WriteFile', preview: preview(args[1], n) }); } } catch (e) { } } });
hook('advapi32.dll', 'RegSetValueExW', { onEnter: function (args) { var name = w(args[1]); var type = 0; try { type = args[3].toInt32(); } catch (e) { } var pv = ''; try { if (type === 1 || type === 2) { pv = w(args[4]); } } catch (e) { } emit({ cat: 'registry', api: 'RegSetValueExW', name: name, preview: pv }); } });

// --- DPAPI use ---
hook('crypt32.dll', 'CryptProtectData', { onEnter: function () { emit({ cat: 'dpapi', api: 'CryptProtectData' }); } });
hook('crypt32.dll', 'CryptUnprotectData', { onEnter: function () { emit({ cat: 'dpapi', api: 'CryptUnprotectData' }); } });

emit({ cat: 'meta', api: 'ready' });
