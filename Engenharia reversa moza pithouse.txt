# =============================================================================
# ENGENHARIA REVERSA MOZA — ANALISE V3: THUNKS + MULTI-BINARIO
# =============================================================================
#
# DESCOBERTAS DA V2:
#   - FirmwareManager.exe importa Tea_Init + Tea_Encrypt, mas NAO Tea_Decrypt
#   - Zero call sites diretos (FF 15) para Tea_Init — usa thunks (call rel32 + jmp indirect)
#   - Nova string no .rdata: 'Gudsen.888' (3 oitos, nao 8!)
#   - "Tea_Init key: " é prefixo de log
#
# QUEM CHAMA Tea_Decrypt ENTAO?
#   Provavelmente: MOZA Pit House.exe ou MOZADeviceService.exe
#
# ESTRATEGIA V3:
#   1. Analisar 3 binarios: FirmwareManager, MOZA Pit House.exe, MOZADeviceService
#   2. Para cada, achar IAT slot de Tea_Init/Encrypt/Decrypt de crypt.dll
#   3. Achar THUNK: sequencia "FF 25 [IAT]" (jmp indirect)
#   4. Achar CALLERS do thunk: "E8 XX XX XX XX" (call rel32)
#   5. Para cada caller, analisar os pushes anteriores (args)
#   6. Se push imm32 -> string, extrair
# =============================================================================

python -m pip install capstone

$scriptPath = "$env:USERPROFILE\Desktop\moza-re\static_v3_thunks.py"

@'
import struct, re, sys
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

TARGETS_FUNCS = ["Tea_Init", "Tea_Encrypt", "Tea_Decrypt"]

BINARIES = [
    Path("C:/Program Files (x86)/MOZA Pit House/bin/FirmwareManager.exe"),
    Path("C:/Program Files (x86)/MOZA Pit House/bin/MOZA Pit House.exe"),
    Path("C:/Program Files (x86)/MOZA Pit House/bin/MOZADeviceService.exe"),
    Path("C:/Program Files (x86)/MOZA Pit House/bin/RacingLab.exe"),
    Path("C:/Program Files (x86)/MOZA Pit House/bin/MOZA Dashboard Studio.exe"),
]

md = Cs(CS_ARCH_X86, CS_MODE_32)

def analyze(exe_path):
    if not exe_path.exists():
        print(f"[skip] {exe_path.name} nao existe")
        return
    print(f"\n{'#'*70}")
    print(f"# ANALISANDO: {exe_path.name}")
    print(f"{'#'*70}")

    data = exe_path.read_bytes()
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
    if machine != 0x14C:
        print(f"  [!] Nao e x86 (machine=0x{machine:X}), pulando")
        return

    num_sec  = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    image_base = struct.unpack_from("<I", data, e_lfanew + 24 + 28)[0]
    sec_off  = e_lfanew + 24 + opt_size

    sections = []
    for i in range(num_sec):
        s = sec_off + i * 40
        name = data[s:s+8].rstrip(b'\x00').decode('ascii', 'replace')
        vaddr = struct.unpack_from("<I", data, s+12)[0]
        vsize = struct.unpack_from("<I", data, s+8)[0]
        raddr = struct.unpack_from("<I", data, s+20)[0]
        rsize = struct.unpack_from("<I", data, s+16)[0]
        sections.append((name, vaddr, vsize, raddr, rsize))

    def rva_to_off(rva):
        for _, va, vs, ra, rs in sections:
            if va <= rva < va + vs: return ra + (rva - va)
        return None
    def va_to_off(va):
        return rva_to_off(va - image_base)

    # Import Directory
    opt_hdr = e_lfanew + 24
    dd = opt_hdr + 96 + 8
    imp_rva = struct.unpack_from("<I", data, dd)[0]
    imp_off = rva_to_off(imp_rva)
    if not imp_off:
        print("  Sem import directory")
        return

    # Achar IAT slots de crypt.dll
    iat_slots = {}  # func -> IAT VA
    i = 0
    while True:
        entry_off = imp_off + i * 20
        if entry_off + 20 > len(data): break
        ilt_rva = struct.unpack_from("<I", data, entry_off)[0]
        iat_rva = struct.unpack_from("<I", data, entry_off + 16)[0]
        name_rva = struct.unpack_from("<I", data, entry_off + 12)[0]
        if ilt_rva == 0 and name_rva == 0: break

        dll_name_off = rva_to_off(name_rva)
        if not dll_name_off:
            i += 1; continue
        end = data.index(b'\x00', dll_name_off)
        dll_name = data[dll_name_off:end].decode('ascii', 'replace').lower()

        if dll_name == "crypt.dll":
            j = 0
            while True:
                ilt_e_off = rva_to_off(ilt_rva) + j * 4
                iat_e_va  = image_base + iat_rva + j * 4
                ilt_val = struct.unpack_from("<I", data, ilt_e_off)[0]
                if ilt_val == 0: break
                sym_name_rva = ilt_val & 0x7FFFFFFF
                if sym_name_rva:
                    sym_off = rva_to_off(sym_name_rva) + 2
                    sym_name = data[sym_off:data.index(b'\x00', sym_off)].decode('ascii', 'replace')
                    if sym_name in TARGETS_FUNCS:
                        iat_slots[sym_name] = iat_e_va
                j += 1
        i += 1

    if not iat_slots:
        print(f"  [!] Nao importa crypt.dll (ou nao usa Tea_*)")
        return

    print(f"  Importa de crypt.dll:")
    for f, va in iat_slots.items():
        print(f"    {f}: IAT slot 0x{va:08X}")

    # .text
    text_sec = next((s for s in sections if s[0] == ".text"), None)
    if not text_sec:
        print("  Sem .text"); return
    text_va = image_base + text_sec[1]
    text_off = text_sec[3]
    text_size = text_sec[4]
    text_bytes = data[text_off:text_off + text_size]

    # Para cada IAT slot, achar THUNK (FF 25 [iat_va]) no .text
    print(f"\n  Buscando thunks (FF 25 -> IAT) no .text ({text_size} bytes)...")
    for func_name, iat_va in iat_slots.items():
        needle = bytes([0xFF, 0x25]) + struct.pack("<I", iat_va)
        thunk_positions = []
        pos = 0
        while True:
            pos = text_bytes.find(needle, pos)
            if pos < 0: break
            thunk_positions.append(pos)
            pos += 1

        # Tambem procurar call direto FF 15
        needle_direct = bytes([0xFF, 0x15]) + struct.pack("<I", iat_va)
        direct_positions = []
        pos = 0
        while True:
            pos = text_bytes.find(needle_direct, pos)
            if pos < 0: break
            direct_positions.append(pos)
            pos += 1

        print(f"\n  === {func_name} ===")
        print(f"    Thunks (FF 25): {len(thunk_positions)}")
        print(f"    Call direto (FF 15): {len(direct_positions)}")

        # Para cada thunk, buscar callers (E8 rel32 -> thunk_va)
        callers_all = []
        for tp in thunk_positions:
            thunk_va = text_va + tp
            # Buscar todas E8 XX XX XX XX onde thunk_va = call_va + 5 + rel32
            for i in range(0, len(text_bytes) - 5):
                if text_bytes[i] == 0xE8:
                    rel = struct.unpack_from("<i", text_bytes, i + 1)[0]
                    target = text_va + i + 5 + rel
                    if target == thunk_va:
                        callers_all.append((text_va + i, thunk_va))

        # Callers diretos tambem
        for dp in direct_positions:
            callers_all.append((text_va + dp, None))

        print(f"    Callers totais: {len(callers_all)}")

        # Analisar os primeiros 15 callers
        for idx, (call_va, thunk_va) in enumerate(callers_all[:15]):
            call_off = call_va - text_va
            # Desmontar 100 bytes ANTES do call
            start = max(0, call_off - 100)
            code = text_bytes[start:call_off + 6]
            code_va = text_va + start
            instrs = list(md.disasm(code, code_va))
            recent = instrs[-16:] if len(instrs) > 16 else instrs

            print(f"\n    --- Call #{idx+1} @ 0x{call_va:X} " + ("(direto)" if not thunk_va else f"(via thunk 0x{thunk_va:X})") + " ---")
            for ins in recent:
                marker = " >>>" if ins.address == call_va else "    "
                print(f"    {marker} 0x{ins.address:08X}: {ins.mnemonic:<7} {ins.op_str}")

            # Detectar pushes
            for ins in reversed(recent[:-1]):
                if ins.mnemonic == "push":
                    op = ins.op_str
                    m = re.match(r'^(0x[0-9a-fA-F]+|-?\d+)$', op)
                    if m:
                        v = int(op, 0) & 0xFFFFFFFF
                        if v > image_base and v < image_base + 0x2000000:
                            off = va_to_off(v)
                            if off:
                                end = data.find(b'\x00', off)
                                if end > 0 and end - off < 200:
                                    s = data[off:end]
                                    try:
                                        printable = all(32 <= b < 127 for b in s)
                                        if printable and len(s) > 0:
                                            print(f"        >> ARG STRING 0x{v:X} = {s.decode('ascii')!r}")
                                            continue
                                    except: pass
                                raw = data[off:off+32]
                                print(f"        >> ARG PTR 0x{v:X} raw: {raw.hex(' ').upper()}")
                            else:
                                print(f"        >> ARG imm 0x{v:X} (fora)")
                        else:
                            print(f"        >> ARG imm 0x{v:X} = {v}")
                    else:
                        print(f"        >> ARG {op}")
                elif ins.mnemonic == "lea":
                    # LEA r, [rip+off]  -- referencia a data
                    print(f"        >> LEA candidato: {ins.op_str}")
                elif ins.mnemonic.startswith("call"):
                    break

for exe in BINARIES:
    try:
        analyze(exe)
    except Exception as e:
        print(f"[ERROR analisando {exe.name}]: {type(e).__name__}: {e}")
'@ | Set-Content -Path $scriptPath -Encoding UTF8

Write-Host "`n=== RODANDO ANALISE V3 EM MULTIPLOS BINARIOS ===" -ForegroundColor Cyan
python $scriptPath
