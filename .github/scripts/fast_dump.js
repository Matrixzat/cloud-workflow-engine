'use strict';
var dumpIdx = 0;

function writeDex(ptr, size, tag) {
    if (size < 0x1000) return;
    try {
        var magic = Memory.readByteArray(ptr, 4);
        var b = new Uint8Array(magic);
        if (b[0]!==0x64||b[1]!==0x65||b[2]!==0x78||b[3]!==0x0a) return;
        var fname = '/sdcard/dex_' + (dumpIdx++) + '_' + tag + '.dex';
        var f = new File(fname, 'wb');
        f.write(Memory.readByteArray(ptr, size));
        f.flush();
        f.close();
        console.log('[+] ' + fname + ' ' + size + ' bytes');
    } catch(e) { console.log('[!] writeDex: ' + e); }
}

// Hook mmap via libc.so module directly (Frida 17 compatible)
try {
    var libc = Process.getModuleByName('libc.so');
    ['mmap64', 'mmap'].forEach(function(sym) {
        var exp = libc.findExportByName(sym);
        if (!exp) return;
        Interceptor.attach(exp, {
            onEnter: function(a) { this.len = a[1].toInt32(); },
            onLeave: function(r) { if (!r.isNull()) writeDex(r, this.len, sym); }
        });
        console.log('[*] hooked libc ' + sym);
    });
} catch(e) { console.log('[!] mmap hook: ' + e); }

// Java hooks — InMemoryDexClassLoader + BaseDexClassLoader
Java.perform(function() {
    console.log('[*] Java.perform running');

    try {
        var IMDCL = Java.use('dalvik.system.InMemoryDexClassLoader');
        IMDCL.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader')
        .implementation = function(buf, cl) {
            var pos = buf.position();
            var size = buf.limit() - pos;
            var arr = Java.array('byte', new Array(size).fill(0));
            buf.get(arr);
            var fos = Java.use('java.io.FileOutputStream')
                .$new('/sdcard/dex_' + (dumpIdx++) + '_imdcl.dex');
            fos.write(arr); fos.flush(); fos.close();
            buf.position(pos);
            console.log('[+] InMemoryDex: ' + size + ' bytes');
            return this.$init(buf, cl);
        };
        console.log('[*] InMemoryDexClassLoader hooked');
    } catch(e) { console.log('[!] IMDCL: ' + e); }

    try {
        var BaseDCL = Java.use('dalvik.system.BaseDexClassLoader');
        BaseDCL.$init.overload('java.lang.String','java.io.File','java.lang.String','java.lang.ClassLoader')
        .implementation = function(dexPath, optDir, libPath, parent) {
            console.log('[+] BaseDex path: ' + dexPath);
            dexPath.toString().split(':').forEach(function(p) {
                try {
                    var File = Java.use('java.io.File');
                    var f = File.$new(p);
                    if (!f.exists() || f.length() < 1024) return;
                    var len = parseInt(f.length());
                    var fis = Java.use('java.io.FileInputStream').$new(f);
                    var data = Java.array('byte', new Array(len).fill(0));
                    fis.read(data); fis.close();
                    var fos = Java.use('java.io.FileOutputStream')
                        .$new('/sdcard/dex_' + (dumpIdx++) + '_bdcl.dex');
                    fos.write(data); fos.flush(); fos.close();
                    console.log('[+] Copied: ' + p + ' (' + len + ' bytes)');
                } catch(e2) { console.log('[!] copy: ' + e2); }
            });
            return this.$init(dexPath, optDir, libPath, parent);
        };
        console.log('[*] BaseDexClassLoader hooked');
    } catch(e) { console.log('[!] BaseDCL: ' + e); }
});
