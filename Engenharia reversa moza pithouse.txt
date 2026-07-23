# =============================================================================
# ENGENHARIA REVERSA MOZA — ANALISE ESTATICA DAS CALL SITES DE Tea_Init
# =============================================================================
#
# CONTEXTO:
#   Frida nao capturou Tea_Init nem em uso normal do Pit House. A logica de
#   firmware provavelmente esta num subprocess que so roda em update real.
#
# NOVA ESTRATEGIA:
#   Fazer analise ESTATICA do FirmwareManager.exe (que importa Tea_Init de
#   crypt.dll). Encontrar cada instrucao "call Tea_Init" e analisar o que
#   e passado como argumento (a chave). Se for uma string constante,
#   ela estara em .rdata do proprio FirmwareManager.exe.
#
# COMO FUNCIONA:
#   1. Localiza a IAT (Import Address Table) — entrada pra crypt.Tea_Init
#   2. Encontra todas instrucoes "call [IAT_addr]" (indireto)
#   3. Para cada call site, olha PUSHes anteriores (argumentos)
#   4. Se argumento e "push imm32" apontando pra string em .rdata, extrai
#   5. Faz mesmo pra Tea_Decrypt e Tea_Encrypt
# =============================================================================

python -m pip install capstone

$scriptPath = "$env:USERPROFILE\Desktop\moza-re\static_call_analysis.py"

@'
import struct
import re
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

EXE = Path("C:/Program Files (x86)/MOZA Pit House/bin/FirmwareManager.exe")
data = EXE.read_bytes()
print(f"FirmwareManager.exe: {len(data)} bytes")

# ============================================================
# Parser PE
# ============================================================
e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
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
def off_to_va(off):
    for _, va, vs, ra, rs in sections:
        if ra <= off < ra + rs: return image_base + va + (off - ra)
    return None

print(f"ImageBase: 0x{image_base:X}")
for name, va, vs, ra, rs in sections:
    print(f"  section {name:<10} VA 0x{image_base+va:08X} size={vs:>8} file 0x{ra:X}")

# ============================================================
# Achar IAT entries para Tea_Init/Encrypt/Decrypt
# Import Directory: data directory index 1
# ============================================================
opt_hdr = e_lfanew + 24
dd = opt_hdr + 96 + 8  # index 1 = Import Directory
imp_rva = struct.unpack_from("<I", data, dd)[0]
imp_off = rva_to_off(imp_rva)
print(f"\nImport Directory RVA=0x{imp_rva:X} off=0x{imp_off:X}")

# Iterar Import Descriptors
TARGETS = ["Tea_Init", "Tea_Encrypt", "Tea_Decrypt"]
iat_entries = {}  # func_name -> VA da IAT entry
i = 0
while True:
    entry_off = imp_off + i * 20
    ilt_rva = struct.unpack_from("<I", data, entry_off)[0]
    iat_rva = struct.unpack_from("<I", data, entry_off + 16)[0]
    name_rva = struct.unpack_from("<I", data, entry_off + 12)[0]
    if ilt_rva == 0 and name_rva == 0: break

    dll_name_off = rva_to_off(name_rva)
    dll_name = data[dll_name_off:data.index(b'\x00', dll_name_off)].decode('ascii', 'replace')

    if dll_name.lower() == "crypt.dll":
        print(f"\n  Import: {dll_name}")
        # Iterar ILT ate 0
        j = 0
        while True:
            ilt_entry_off = rva_to_off(ilt_rva) + j * 4
            iat_entry_va  = image_base + iat_rva + j * 4
            ilt_val = struct.unpack_from("<I", data, ilt_entry_off)[0]
            if ilt_val == 0: break
            # Nome do simbolo (offset+2 pra pular ordinal hint)
            sym_name_rva = ilt_val & 0x7FFFFFFF
            if sym_name_rva:
                sym_off = rva_to_off(sym_name_rva) + 2
                sym_name = data[sym_off:data.index(b'\x00', sym_off)].decode('ascii', 'replace')
                if sym_name in TARGETS:
                    iat_entries[sym_name] = iat_entry_va
                    print(f"    {sym_name}: IAT slot @ VA 0x{iat_entry_va:X}")
            j += 1
    i += 1

# ============================================================
# Buscar todas call sites de cada IAT entry no .text
# call qword ptr [addr]  em 32-bit = FF 15 XX XX XX XX (indireto)
# ============================================================
md = Cs(CS_ARCH_X86, CS_MODE_32)

# Localizar .text
text_sec = next(s for s in sections if s[0] == ".text")
text_va = image_base + text_sec[1]
text_off = text_sec[3]
text_size = text_sec[4]
text_bytes = data[text_off:text_off + text_size]

print(f"\n.text: VA 0x{text_va:X} size {text_size} file 0x{text_off:X}\n")

for func_name, iat_va in iat_entries.items():
    print(f"\n{'='*70}")
    print(f"=== Call sites de {func_name} (IAT @ 0x{iat_va:X}) ===")
    print('='*70)

    # Buscar "FF 15 <LE de iat_va>" no .text
    needle = bytes([0xFF, 0x15]) + struct.pack("<I", iat_va)
    positions = []
    pos = 0
    while True:
        pos = text_bytes.find(needle, pos)
        if pos < 0: break
        positions.append(pos)
        pos += 1

    print(f"Encontradas {len(positions)} call sites (FF 15 indirect)")

    for site_idx, p in enumerate(positions):
        call_va = text_va + p
        print(f"\n  --- Call site #{site_idx+1} @ VA 0x{call_va:X} ---")
        # Analisar 60 bytes ANTES do call para ver os push
        start = max(0, p - 80)
        code = text_bytes[start : p + 6]
        code_va = text_va + start
        instrs = list(md.disasm(code, code_va))
        # Mostrar so as ultimas 12 instrucoes
        instrs = instrs[-14:]
        for ins in instrs:
            marker = "  >>>" if ins.address == call_va else "     "
            print(f"{marker} 0x{ins.address:08X}: {ins.mnemonic:<7} {ins.op_str}")

        # Detectar push imm32 recentes — potenciais args
        # Args em cdecl: ultimo push antes de call e o PRIMEIRO argumento (arg0)
        push_imms = []
        for ins in reversed(instrs[:-1]):  # exclude the call itself
            if ins.mnemonic == "push":
                op = ins.op_str
                m = re.match(r'^(0x[0-9a-fA-F]+|\d+)$', op)
                if m:
                    v = int(op, 0)
                    push_imms.append((ins.address, v))
                elif op in ("eax", "ebx", "ecx", "edx", "esi", "edi"):
                    push_imms.append((ins.address, f"reg:{op}"))
                # Parar apos alguns pushes
                if len(push_imms) >= 4: break
            elif ins.mnemonic.startswith("call"):
                break  # outra call, parar

        for addr, val in push_imms:
            if isinstance(val, int) and val > 0x400000:
                # Tentar interpretar como VA — ler string na posicao
                off = va_to_off(val)
                if off:
                    end = data.find(b'\x00', off)
                    if end > 0 and end - off < 200:
                        s = data[off:end]
                        # se e ASCII imprimivel
                        try:
                            printable = all(32 <= b < 127 for b in s)
                            if printable and len(s) > 0:
                                print(f"        arg pointer 0x{val:08X} -> {s.decode('ascii')!r}")
                                continue
                        except: pass
                    # senao mostrar bytes crus
                    raw = data[off:off+32]
                    print(f"        arg pointer 0x{val:08X} -> raw: {raw.hex(' ').upper()}")
                else:
                    print(f"        arg imm 0x{val:08X} (fora do binario)")
            elif isinstance(val, int):
                print(f"        arg imm 0x{val:X} = {val}")
            else:
                print(f"        arg {val}")

print("\n\n=== BUSCA COMPLEMENTAR: strings 'chave-suspeitas' no .rdata ===\n")
rdata_sec = next((s for s in sections if s[0] == ".rdata"), None)
if rdata_sec:
    rd = data[rdata_sec[3] : rdata_sec[3] + rdata_sec[4]]
    # Buscar strings com "key", "Tea", "cipher", "Gudsen"
    for kw in [b"Gudsen", b"key", b"Key", b"cipher", b"Tea", b"88888", b"secret"]:
        pos = 0
        while True:
            i = rd.find(kw, pos)
            if i < 0: break
            # Extrair a string em volta (parar em NUL)
            start = i
            while start > 0 and 32 <= rd[start-1] < 127: start -= 1
            end = i
            while end < len(rd) and 32 <= rd[end] < 127: end += 1
            s = rd[start:end]
            if 5 < len(s) < 200:
                print(f"  '{s.decode('ascii', 'replace')}'")
            pos = end + 1
'@ | Set-Content -Path $scriptPath -Encoding UTF8

Write-Host "`n=== RODANDO ANALISE ESTATICA ===" -ForegroundColor Cyan
python $scriptPath
