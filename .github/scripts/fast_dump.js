
'use strict';
var dumpIdx = 0;

function writeDex(ptr, size, tag) {
    if (size < 0x100) return;
    try {
        var header = ptr.readByteArray(8);
        var b = new Uint8Array(header);
        // Must start with DEX magic: 64 65 78 0a
        if (b[0]!==0x64||b[1]!==0x65||b[2]!==0x78||b[3]!==0x0a) return;
        var fname = '/sdcard/dex_' + (dumpIdx++) + '_' + tag + '.dex';
        var data = ptr.readByteArray(size);
        var f = new File(fname, 'wb');
        f.write(data);
        f.close();
        console.log('[+] DEX saved: ' + fname + '  size=' + size);
    } catch(e) { }
}

// Hook 1: mmap — catches Jiagu when it maps decrypted DEX into memory
var mmapPtr = Module.findExportByName(null, 'mmap');
if (mmapPtr) {
    Interceptor.attach(mmapPtr, {
        onEnter: function(a) { this.len = a[1].toInt32(); },
        onLeave: function(r) {
            if (!r.isNull() && r.toInt32() !== -1)
                writeDex(r, this.len, 'mmap');
        }
    });
    console.log('[*] mmap hook installed');
}

// Hook 2: mmap64 variant
var mmap64Ptr = Module.findExportByName(null, 'mmap64');
if (mmap64Ptr) {
    Interceptor.attach(mmap64Ptr, {
        onEnter: function(a) { this.len = a[1].toInt32(); },
        onLeave: function(r) {
            if (!r.isNull() && r.toInt32() !== -1)
                writeDex(r, this.len, 'mmap64');
        }
    });
}

// Hook 3: Java InMemoryDexClassLoader (Android 8+, API 26+)
Java.perform(function() {
    console.log('[*] Java hooks installing...');
    try {
        var IMDCL = Java.use('dalvik.system.InMemoryDexClassLoader');
        IMDCL.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader')
        .implementation = function(buf, cl) {
            var size = buf.remaining();
            var jbytes = Java.array('byte', {length: size});
            buf.get(jbytes);
            console.log('[+] InMemoryDexClassLoader: ' + size + ' bytes');
            var fos = Java.use('java.io.FileOutputStream')
                .$new('/sdcard/dex_' + (dumpIdx++) + '_imdcl.dex');
            fos.write(jbytes);
            fos.close();
            buf.rewind();
            return this.$init(buf, cl);
        };
        console.log('[*] InMemoryDexClassLoader hooked');
    } catch(e) { console.log('[!] IMDCL: ' + e); }

    // Hook 4: BaseDexClassLoader — catches file-based DEX loading
    try {
        var BaseDCL = Java.use('dalvik.system.BaseDexClassLoader');
        BaseDCL.$init.overload('java.lang.String','java.io.File','java.lang.String','java.lang.ClassLoader')
        .implementation = function(dexPath, optDir, libPath, parent) {
            console.log('[+] BaseDexClassLoader: ' + dexPath);
            dexPath.toString().split(':').forEach(function(p) {
                try {
                    var f = Java.use('java.io.File').$new(p);
                    if (f.exists() && f.length() > 512) {
                        var len = f.length();
                        var fis = Java.use('java.io.FileInputStream').$new(f);
                        var data = Java.array('byte', {length: parseInt(len)});
                        fis.read(data); fis.close();
                        var fos = Java.use('java.io.FileOutputStream')
                            .$new('/sdcard/dex_' + (dumpIdx++) + '_bdcl.dex');
                        fos.write(data); fos.close();
                        console.log('[+] Copied: ' + p);
                    }
                } catch(e2) {}
            });
            return this.$init(dexPath, optDir, libPath, parent);
        };
        console.log('[*] BaseDexClassLoader hooked');
    } catch(e) { console.log('[!] BaseDCL: ' + e); }
});
