'use strict';
var dumpIdx = 0;

// Native file I/O — avoids Frida File API (broken in Frida 17 QuickJS)
var libc    = Process.getModuleByName('libc.so');
var _fopen  = new NativeFunction(libc.getExportByName('fopen'),  'pointer', ['pointer','pointer']);
var _fwrite = new NativeFunction(libc.getExportByName('fwrite'), 'size_t',  ['pointer','size_t','size_t','pointer']);
var _fclose = new NativeFunction(libc.getExportByName('fclose'), 'int',     ['pointer']);
var WB_MODE = Memory.allocUtf8String('wb');

function saveMem(ptr, size, tag) {
    if (size < 0x1000) return;
    try {
        var hdr = ptr.readByteArray(4);
        if (!hdr) return;
        var u = new Uint8Array(hdr);
        // DEX magic: 64 65 78 0a
        if (u[0]!==0x64||u[1]!==0x65||u[2]!==0x78||u[3]!==0x0a) return;
        var fname = '/sdcard/dex_' + (dumpIdx++) + '_' + tag + '.dex';
        var fnameP = Memory.allocUtf8String(fname);
        var fp = _fopen(fnameP, WB_MODE);
        if (!fp.isNull()) {
            _fwrite(ptr, 1, size, fp);
            _fclose(fp);
            console.log('[+] DEX ' + fname + ' (' + size + 'b)');
        }
    } catch(e) { console.log('[!] saveMem: ' + e); }
}

// Hook mmap / mmap64 in libc
['mmap64','mmap'].forEach(function(sym) {
    var exp = libc.findExportByName(sym);
    if (!exp) return;
    Interceptor.attach(exp, {
        onEnter: function(a) { this.len = a[1].toInt32(); },
        onLeave: function(r)  { if (!r.isNull()) saveMem(r, this.len, sym); }
    });
    console.log('[*] hooked libc.' + sym);
});

// Java hooks
Java.perform(function() {
    console.log('[*] Java.perform running');

    // Hook InMemoryDexClassLoader (Android 8+)
    try {
        var IMDCL = Java.use('dalvik.system.InMemoryDexClassLoader');
        IMDCL.$init.overload('java.nio.ByteBuffer','java.lang.ClassLoader')
        .implementation = function(buf, cl) {
            try {
                var pos  = buf.position();
                var size = buf.limit() - pos;
                var outP = '/sdcard/dex_' + (dumpIdx++) + '_imdcl.dex';
                // Write via channel to avoid large JS array
                var BAOS = Java.use('java.io.ByteArrayOutputStream');
                var Channels = Java.use('java.nio.channels.Channels');
                var baos = BAOS.$new(size);
                var chan = Channels.newChannel(baos);
                chan.write(buf.duplicate());
                chan.close();
                var bytes = baos.toByteArray();
                var FOS = Java.use('java.io.FileOutputStream');
                var fos = FOS.$new(outP);
                fos.write(bytes); fos.flush(); fos.close();
                console.log('[+] IMDCL: ' + size + 'b -> ' + outP);
            } catch(e) { console.log('[!] IMDCL write: ' + e); }
            return this.$init(buf, cl);
        };
        console.log('[*] IMDCL hooked');
    } catch(e) { console.log('[!] IMDCL: ' + e); }

    // Hook BaseDexClassLoader — file-based DEX
    try {
        var BaseDCL = Java.use('dalvik.system.BaseDexClassLoader');
        BaseDCL.$init.overload('java.lang.String','java.io.File','java.lang.String','java.lang.ClassLoader')
        .implementation = function(dp, od, lp, par) {
            try {
                dp.toString().split(':').forEach(function(p) {
                    try {
                        var File = Java.use('java.io.File');
                        var f = File.$new(p);
                        if (!f.exists() || f.length() < 1024) return;
                        var dst = '/sdcard/dex_' + (dumpIdx++) + '_bdcl.dex';
                        // Use Runtime.exec to copy file
                        var RT = Java.use('java.lang.Runtime');
                        RT.getRuntime().exec(['/system/bin/cp', p, dst]).waitFor();
                        console.log('[+] BaseDex cp: ' + p + ' -> ' + dst);
                    } catch(e2) { console.log('[!] BaseDex cp: ' + e2); }
                });
            } catch(e) { console.log('[!] BaseDCL: ' + e); }
            return this.$init(dp, od, lp, par);
        };
        console.log('[*] BaseDCL hooked');
    } catch(e) { console.log('[!] BaseDCL hook: ' + e); }
});
