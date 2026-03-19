import zipfile, struct, os, sys, shutil, random, subprocess, tempfile

APK_PATH = os.environ['CBE_APK_PATH']
XOR_KEY  = 0xA3
# 52-byte armor block sentinel: pay_len(4) + key(32×0xCB) + iv(16×0xDB)
ARMOR_SENTINEL = struct.pack('<I', 0xDEADBEEF) + bytes([0xCB]*32) + bytes([0xDB]*16)
SENTINEL = ARMOR_SENTINEL  # kept for find_sym fallback compatibility

DART_SYMS = [
    '_kDartVmSnapshotData',
    '_kDartIsolateSnapshotData',
    '_kDartVmSnapshotInstructions',
    '_kDartIsolateSnapshotInstructions',
    '_kDartSnapshotBuildId',
]

# ── ELF helpers ──────────────────────────────────────────────────────────────
def parse_loads(data):
    if data[:4] != b'\x7fELF': return None, []
    is64 = (data[4] == 2)
    e_phoff = struct.unpack_from('<Q' if is64 else '<I', data, 32 if is64 else 28)[0]
    e_phentsz = struct.unpack_from('<H', data, 54 if is64 else 42)[0]
    e_phnum   = struct.unpack_from('<H', data, 56 if is64 else 44)[0]
    loads = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsz
        if struct.unpack_from('<I', data, off)[0] != 1: continue
        if is64:
            po = struct.unpack_from('<Q', data, off+8)[0]
            pv = struct.unpack_from('<Q', data, off+16)[0]
            ps = struct.unpack_from('<Q', data, off+32)[0]
        else:
            po = struct.unpack_from('<I', data, off+4)[0]
            pv = struct.unpack_from('<I', data, off+8)[0]
            ps = struct.unpack_from('<I', data, off+16)[0]
        loads.append((pv, po, ps))
    return is64, loads

def v2f(loads, va):
    for pv, po, ps in loads:
        if pv <= va < pv + ps:
            return po + (va - pv)
    return None

def get_dynamic(data, is64, loads, e_phoff, e_phentsz, e_phnum):
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsz
        if struct.unpack_from('<I', data, off)[0] == 2:
            return struct.unpack_from('<Q' if is64 else '<I', data, off+(8 if is64 else 4))[0]
    return None

def parse_dynstrtab(data):
    is64, loads = parse_loads(data)
    if is64 is None: return None, None, None
    e_phoff   = struct.unpack_from('<Q' if is64 else '<I', data, 32 if is64 else 28)[0]
    e_phentsz = struct.unpack_from('<H', data, 54 if is64 else 42)[0]
    e_phnum   = struct.unpack_from('<H', data, 56 if is64 else 44)[0]
    dyn_va = get_dynamic(data, is64, loads, e_phoff, e_phentsz, e_phnum)
    if dyn_va is None: return None, None, None
    strtab_va = strsz = symtab_va = 0
    off = dyn_va
    while True:
        tag = struct.unpack_from('<q' if is64 else '<i', data, off)[0]
        val = struct.unpack_from('<Q' if is64 else '<I', data, off+(8 if is64 else 4))[0]
        if tag == 0: break
        if tag == 5:  strtab_va = val
        if tag == 10: strsz = val
        if tag == 6:  symtab_va = val
        off += 16 if is64 else 8
    strtab_off = v2f(loads, strtab_va)
    symtab_off = v2f(loads, symtab_va) if symtab_va else None
    return strtab_off, strsz, symtab_off

def find_sym(data, name):
    is64, loads = parse_loads(data)
    if is64 is None: return None
    e_phoff   = struct.unpack_from('<Q' if is64 else '<I', data, 32 if is64 else 28)[0]
    e_phentsz = struct.unpack_from('<H', data, 54 if is64 else 42)[0]
    e_phnum   = struct.unpack_from('<H', data, 56 if is64 else 44)[0]
    dyn_va = get_dynamic(data, is64, loads, e_phoff, e_phentsz, e_phnum)
    if dyn_va is None: return None
    strtab_va = strsz = symtab_va = 0
    off = dyn_va
    while True:
        tag = struct.unpack_from('<q' if is64 else '<i', data, off)[0]
        val = struct.unpack_from('<Q' if is64 else '<I', data, off+(8 if is64 else 4))[0]
        if tag == 0: break
        if tag == 5:  strtab_va = val
        if tag == 10: strsz = val
        if tag == 6:  symtab_va = val
        off += 16 if is64 else 8
    symtab_off = v2f(loads, symtab_va)
    strtab_off = v2f(loads, strtab_va)
    str_end = strtab_off + strsz
    sym_sz = 24 if is64 else 16
    off = symtab_off
    while off + sym_sz <= len(data):
        st_name = struct.unpack_from('<I', data, off)[0]
        st_val  = struct.unpack_from('<Q' if is64 else '<I', data, off+(8 if is64 else 4))[0]
        noff = strtab_off + st_name
        if noff < str_end:
            end = data.index(b'\x00', noff)
            if data[noff:end].decode('utf-8', errors='replace') == name:
                return v2f(loads, st_val)
        off += sym_sz
        if off > symtab_off + 0x200000: break
    return None

# ── Protection steps ──────────────────────────────────────────────────────────

def step_scramble_dynstr(data):
    """Step A: Rename all Dart symbol names in .dynstr to random garbage."""
    strtab_off, strsz, _ = parse_dynstrtab(data)
    if strtab_off is None:
        print('  [A] SKIP: .dynstr not located', flush=True); return
    scrambled = 0
    for name in DART_SYMS:
        nb = name.encode() + b'\x00'
        pos = bytes(data).find(nb, strtab_off, strtab_off + strsz)
        if pos == -1:
            print(f'  [A] not found: {name}', flush=True); continue
        # Same-length lowercase random name
        rand = bytes([random.randint(0x61, 0x7a) for _ in range(len(name))]) + b'\x00'
        data[pos:pos+len(nb)] = rand
        print(f'  [A] {name} → {rand[:-1].decode()}', flush=True)
        scrambled += 1
    print(f'  [A] Scrambled {scrambled}/{len(DART_SYMS)} symbol names ✓', flush=True)


# ── AES-256-CTR encryption via openssl (no padding — output same size as input) ──
def aes256_ctr_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    fd_in,  in_path  = tempfile.mkstemp()
    fd_out, out_path = tempfile.mkstemp()
    try:
        os.write(fd_in, data)
        os.close(fd_in);  fd_in  = -1
        os.close(fd_out); fd_out = -1
        subprocess.run(
            ['openssl', 'enc', '-aes-256-ctr', '-nosalt', '-nopad',
             '-K', key.hex(), '-iv', iv.hex(),
             '-in', in_path, '-out', out_path],
            check=True, capture_output=True
        )
        with open(out_path, 'rb') as f:
            return f.read()
    finally:
        if fd_in  != -1: os.close(fd_in)
        if fd_out != -1: os.close(fd_out)
        for p in (in_path, out_path):
            try: os.unlink(p)
            except OSError: pass

def step_zero_snapshot(data, snap_off):
    """Steps B+C: Zero hash, zero features string. Return payload_off."""
    FIXED = 20
    hash_off = snap_off + FIXED
    # Measure hash length: read until non-hex or null
    hash_len = 0
    for i in range(64):
        b = data[hash_off + i]
        if b == 0:
            hash_len = i; break
        if not (0x30 <= b <= 0x39 or 0x61 <= b <= 0x66 or 0x41 <= b <= 0x46):
            hash_len = i; break
    else:
        hash_len = 32
    hash_str = bytes(data[hash_off:hash_off+hash_len]).decode('ascii', errors='?')
    print(f'  [B] Hash ({hash_len}b) at 0x{hash_off:x}: "{hash_str}"', flush=True)
    # Zero hash bytes
    for i in range(hash_len): data[hash_off + i] = 0x00
    print(f'  [B] Hash zeroed ✓', flush=True)
    # Features string starts after hash+null
    feat_off = hash_off + hash_len + 1
    feat_end = feat_off
    while feat_end < len(data) and data[feat_end] != 0: feat_end += 1
    feat_str = bytes(data[feat_off:feat_end]).decode('ascii', errors='?')
    print(f'  [C] Features ({feat_end-feat_off}b): "{feat_str[:70]}..."', flush=True)
    # Zero features (prevents Dart version + arch fingerprinting)
    for i in range(feat_off, feat_end): data[i] = 0x00
    print(f'  [C] Features zeroed ✓', flush=True)
    return feat_end + 1  # payload starts after features+null

def step_encrypt_payload(data, payload_off, pay_len, has_native, key, iv):
    """Step D: XOR then AES-256-CTR encrypt payload. Only if libcbe_native.so is bundled."""
    if not has_native:
        print(f'  [D] XOR skipped — libcbe_native.so not in APK', flush=True)
        return 0
    if pay_len <= 0:
        print(f'  [D] XOR skipped — payload length invalid', flush=True)
        return 0
    print(f'  [D] XOR-encrypting {pay_len} bytes at 0x{payload_off:x} (key=0x{XOR_KEY:02x})...', flush=True)
    # Step 1: XOR 0xA3
    for i in range(pay_len):
        data[payload_off + i] ^= XOR_KEY
    # Step 2: AES-256-CTR (same size output, no padding)
    plain_bytes = bytes(data[payload_off:payload_off + pay_len])
    enc_bytes = aes256_ctr_encrypt(plain_bytes, key, iv)
    data[payload_off:payload_off + pay_len] = bytearray(enc_bytes)
    print(f'  [D] XOR + AES-256-CTR encrypted {pay_len} bytes ✓', flush=True)
    return pay_len

def step_patch_native_sentinel(libnative_data, pay_len):
    """Step E: Patch _cbe_armor block (52 bytes: pay_len+key+iv) in libcbe_native.so."""
    pos = bytes(libnative_data).find(SENTINEL)
    if pos == -1:
        sym_off = find_sym(libnative_data, '_cbe_armor')
        if sym_off is not None: pos = sym_off
    if pos == -1:
        print(f'  [E] WARNING: sentinel 0xDEADBEEF not found in libcbe_native.so', flush=True)
        return
    struct.pack_into('<I', libnative_data, pos, pay_len)
    print(f'  [E] Armor block patched: pay_len={pay_len}, AES key+IV injected at 0x{pos:x} ✓', flush=True)

# ── Main ─────────────────────────────────────────────────────────────────────
DART_MAGIC = bytes([0xF5, 0xF5, 0xDC, 0xDC])

with zipfile.ZipFile(APK_PATH, 'r') as z:
    names = z.namelist()
    abis  = [n.split('/')[1] for n in names
             if n.startswith('lib/') and n.endswith('/libapp.so')]

patched = 0
for abi in abis:
    libapp_name    = f'lib/{abi}/libapp.so'
    libnative_name = f'lib/{abi}/libcbe_native.so'
    if libapp_name not in names: continue

    print(f'\n{"="*60}', flush=True)
    print(f'Layer 3 → {abi}', flush=True)
    print(f'{"="*60}', flush=True)

    with zipfile.ZipFile(APK_PATH, 'r') as z:
        libapp_data    = bytearray(z.read(libapp_name))
        has_native     = libnative_name in names
        libnative_data = bytearray(z.read(libnative_name)) if has_native else None
    print(f'libcbe_native.so present: {has_native}', flush=True)

    # A — Scramble ELF dynamic symbol names
    step_scramble_dynstr(libapp_data)

    # B+C — Zero hash + features in every snapshot
    snap_positions = []
    pos = 0
    while True:
        idx = bytes(libapp_data).find(DART_MAGIC, pos)
        if idx == -1: break
        snap_positions.append(idx)
        pos = idx + 4
    print(f'\nFound {len(snap_positions)} snapshot(s) via magic at: '
          f'{["0x"+hex(o) for o in snap_positions]}', flush=True)

    # ── B+C: zero hash + features in every snapshot ───────────────────────────
    isolate_payload_off = None
    for snap_off in snap_positions:
        print(f'\nSnapshot @ 0x{snap_off:x}:', flush=True)
        payload_off = step_zero_snapshot(libapp_data, snap_off)
        isolate_payload_off = payload_off  # last one = IsolateSnapshot (highest offset)

    # ── D: XOR + AES-256-CTR encrypt ONLY the IsolateSnapshot payload ─────────
    # Generate a fresh random 32-byte AES key and 16-byte IV for every build.
    # VmSnapshot comes first (lower offset) — skipped to avoid double-encrypt.
    # Only the IsolateSnapshot (last/highest offset) owns the object pool that
    # blutter targets — encrypt only that.
    aes_key = os.urandom(32)  # unique per build
    aes_iv  = os.urandom(16)  # unique per build
    total_encrypted = 0
    if isolate_payload_off is not None:
        iso_snap_off = snap_positions[-1]  # last magic hit = IsolateSnapshot
        print(f'\nEncrypting IsolateSnapshot payload @ 0x{iso_snap_off:x}', flush=True)
        pay_len = len(libapp_data) - isolate_payload_off
        total_encrypted = step_encrypt_payload(
            libapp_data, isolate_payload_off, pay_len, has_native, aes_key, aes_iv)

    # E — Patch armor block (pay_len + AES key + IV) in libcbe_native.so
    if has_native and total_encrypted > 0 and libnative_data:
        step_patch_native_sentinel(libnative_data, total_encrypted, aes_key, aes_iv)

    # Write back
    print(f'\nRewriting APK...', flush=True)
    tmp = APK_PATH + '.tmp'
    with zipfile.ZipFile(APK_PATH, 'r') as zin, \
         zipfile.ZipFile(tmp, 'w') as zout:
        for item in zin.infolist():
            if item.filename == libapp_name:
                item.compress_type = zipfile.ZIP_STORED
                zout.writestr(item, bytes(libapp_data))
            elif item.filename == libnative_name and libnative_data is not None:
                item.compress_type = zipfile.ZIP_STORED
                zout.writestr(item, bytes(libnative_data))
            else:
                zout.writestr(item, zin.read(item.filename),
                              compress_type=item.compress_type)
    shutil.move(tmp, APK_PATH)
    print(f'Layer 3: {abi} complete ✓', flush=True)
    patched += 1

print(f'\nLayer 3: done — {patched} ABI(s) protected ✓', flush=True)
sys.exit(0)
