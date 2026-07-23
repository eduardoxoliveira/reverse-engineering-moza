# =============================================================================
# ENGENHARIA REVERSA MOZA — ANALISE V5: RASTREIO DE MAP + IAT NAMES + CALLERS
# =============================================================================
#
# DESCOBERTAS DA V4:
#   - Nenhuma string hardcoded na funcao 0xA31750 e a chave
#   - Chave vem de MAP/HASH LOOKUP (call 0x401992)
#   - std::string em [ebp-0x80] e construido a partir de outro std::string
#     em [ebp-0xcc] ou [ebp-0xc8]
#
# V5 (multi-target):
#   A) Resolve nomes dos IAT slots referenciados (msvcp140.dll, etc)
#      pra saber quais metodos de std::string sao usados
#   B) Desmonta a funcao interna 0x401992 (map lookup?)
#   C) Desmonta funcao INTEIRA 0xA31750 (847 instrs) — inicio ao fim
#   D) Busca CALLERS da funcao 0xA31750 (quem passa arg com a chave)
#   E) Extrai strings do binario com padroes de chave (16 chars hex, base64)
# =============================================================================

python -m pip install capstone

# Start-Transcript
$logPath = "$env:USERPROFILE\Desktop\moza-re\output_v5.txt"
Start-Transcript -Path $logPath -Force -IncludeInvocationHeader | Out-Null
Write-Host "`n=== Log em: $logPath ===`n"

$scriptPath = "$env:USERPROFILE\Desktop\moza-re\static_v5_deep.py"

@'
import struct, re
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

EXE = Path("C:/Program Files (x86)/MOZA Pit House/bin/FirmwareManager.exe")
FUNC_START = 0xA31750
CALL_INTERNAL = 0x401992
IAT_INTERESTS = [0xE9B148, 0xE9B14C, 0xE9B2C0, 0xE9B150, 0xE9B12C, 0xE9B138, 0xE9B420, 0xE9B380, 0xE9B14C]

data = EXE.read_bytes()
md = Cs(CS_ARCH_X86, CS_MODE_32)

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

def va_to_off(va):
    for _, vaddr, vsize, raddr, rsize in sections:
        if vaddr + image_base <= va < vaddr + image_base + vsize:
            return raddr + (va - image_base - vaddr)
    return None

def read_string_at_va(va, max_len=256):
    off = va_to_off(va)
    if off is None: return None
    end = data.find(b'\x00', off, off + max_len)
    if end < 0: end = off + max_len
    s = data[off:end]
    if len(s) < 1 or not all(32 <= b < 127 for b in s): return None
    return s.decode('ascii')

text_sec = next(s for s in sections if s[0] == ".text")
text_va = image_base + text_sec[1]
text_off = text_sec[3]
text_bytes = data[text_off:text_off + text_sec[4]]

# ============================================================
# A) RESOLVER NOMES DOS IAT SLOTS
# ============================================================
print("="*80)
print("A) RESOLVENDO NOMES DOS IAT SLOTS")
print("="*80)

opt_hdr = e_lfanew + 24
imp_rva = struct.unpack_from("<I", data, opt_hdr + 96 + 8)[0]
imp_off = va_to_off(image_base + imp_rva)

iat_names = {}  # VA -> (dll_name, func_name)
i = 0
while True:
    entry_off = imp_off + i * 20
    if entry_off + 20 > len(data): break
    ilt_rva = struct.unpack_from("<I", data, entry_off)[0]
    iat_rva = struct.unpack_from("<I", data, entry_off + 16)[0]
    name_rva = struct.unpack_from("<I", data, entry_off + 12)[0]
    if ilt_rva == 0 and name_rva == 0: break
    dll_off = va_to_off(image_base + name_rva)
    if not dll_off: i += 1; continue
    dll_name = data[dll_off:data.index(b'\x00', dll_off)].decode('ascii', 'replace')

    j = 0
    while True:
        ilt_e_off = va_to_off(image_base + ilt_rva) + j * 4
        iat_e_va = image_base + iat_rva + j * 4
        ilt_val = struct.unpack_from("<I", data, ilt_e_off)[0]
        if ilt_val == 0: break
        sym_rva = ilt_val & 0x7FFFFFFF
        if sym_rva and not (ilt_val & 0x80000000):
            sym_off = va_to_off(image_base + sym_rva) + 2
            sym_name = data[sym_off:data.index(b'\x00', sym_off)].decode('ascii', 'replace')
            iat_names[iat_e_va] = (dll_name, sym_name)
        j += 1
    i += 1

print(f"\nIAT slots interessantes na funcao 0xA31750:\n")
for va in IAT_INTERESTS:
    if va in iat_names:
        dll, sym = iat_names[va]
        # Tentar demangle basico se comeca com ?
        display = sym if not sym.startswith("?") else sym[:120]
        print(f"  [0x{va:X}] {dll} :: {display}")
    else:
        print(f"  [0x{va:X}] (nao achado)")

# ============================================================
# B) DESMONTAR FUNCAO INTERNA 0x401992
# ============================================================
print("\n" + "="*80)
print(f"B) FUNCAO INTERNA 0x{CALL_INTERNAL:X}")
print("="*80)

off = CALL_INTERNAL - text_va
code = text_bytes[off:off + 500]
count = 0
for ins in md.disasm(code, CALL_INTERNAL):
    op_str = ins.op_str
    # Resolver call target
    if ins.mnemonic == "call":
        m = re.search(r'\[0x([0-9a-fA-F]+)\]', op_str)
        if m:
            va = int(m.group(1), 16)
            if va in iat_names:
                op_str += f"  ; {iat_names[va][1][:60]}"
    print(f"  0x{ins.address:08X}: {ins.mnemonic:<8} {op_str}")
    count += 1
    if ins.mnemonic in ("ret", "retn") or count > 60: break

# ============================================================
# C) DESMONTAR FUNCAO INTEIRA 0xA31750 (com nomes IAT resolvidos)
# ============================================================
print("\n" + "="*80)
print(f"C) FUNCAO 0x{FUNC_START:X} — INTEIRA COM NOMES IAT")
print("="*80)

off = FUNC_START - text_va
code = text_bytes[off:off + 8000]
count = 0
for ins in md.disasm(code, FUNC_START):
    op_str = ins.op_str
    note = ""
    if ins.mnemonic == "call":
        m = re.search(r'\[0x([0-9a-fA-F]+)\]', op_str)
        if m:
            va = int(m.group(1), 16)
            if va in iat_names:
                note = f"  ; {iat_names[va][1][:80]}"
        # Tambem calls diretos
        m2 = re.match(r'^0x([0-9a-fA-F]+)$', op_str)
        if m2:
            va = int(m2.group(1), 16)
            note = f"  ; internal @ 0x{va:X}"
    # push imm32 -> string
    if ins.mnemonic == "push":
        m = re.match(r'^(0x[0-9a-fA-F]+)$', op_str)
        if m:
            v = int(m.group(1), 16)
            if v > image_base:
                s = read_string_at_va(v)
                if s: note = f"  ; '{s}'"
    marker = " *** CALL Tea_Init ***" if ins.address == 0xA31B70 else ""
    marker += " *** CALL Tea_Encrypt ***" if ins.address == 0xA31ECA else ""
    print(f"  0x{ins.address:08X}: {ins.mnemonic:<8} {op_str}{note}{marker}")
    count += 1
    if ins.mnemonic in ("ret", "retn") and count > 200: break
    if count > 900: break

# ============================================================
# D) BUSCAR CALLERS DA FUNCAO 0xA31750
# ============================================================
print("\n" + "="*80)
print(f"D) CALLERS DA FUNCAO 0x{FUNC_START:X}")
print("="*80)

# Buscar E8 rel32 -> FUNC_START
callers = []
for i in range(0, len(text_bytes) - 5):
    if text_bytes[i] == 0xE8:
        rel = struct.unpack_from("<i", text_bytes, i + 1)[0]
        target = text_va + i + 5 + rel
        if target == FUNC_START:
            callers.append(text_va + i)

print(f"\nEncontrados {len(callers)} callers:\n")
for idx, cva in enumerate(callers[:10]):
    print(f"\n--- Caller #{idx+1} @ 0x{cva:X} ---")
    # Desmontar 60 instrs antes
    start_off = max(0, cva - text_va - 200)
    code = text_bytes[start_off:cva - text_va + 6]
    code_va = text_va + start_off
    all_ins = list(md.disasm(code, code_va))
    for ins in all_ins[-20:]:
        op_str = ins.op_str
        note = ""
        if ins.mnemonic == "push":
            m = re.match(r'^(0x[0-9a-fA-F]+)$', op_str)
            if m:
                v = int(m.group(1), 16)
                if v > image_base:
                    s = read_string_at_va(v)
                    if s: note = f"  ; '{s}'"
        if ins.mnemonic == "call":
            m = re.search(r'\[0x([0-9a-fA-F]+)\]', op_str)
            if m:
                va = int(m.group(1), 16)
                if va in iat_names:
                    note = f"  ; {iat_names[va][1][:60]}"
        marker = "  >>>" if ins.address == cva else "     "
        print(f"{marker} 0x{ins.address:08X}: {ins.mnemonic:<8} {op_str}{note}")

# ============================================================
# E) BUSCAR CANDIDATOS A CHAVE NO BINARIO
# ============================================================
print("\n" + "="*80)
print("E) STRINGS COM PADRAO DE CHAVE NO BINARIO")
print("="*80)

# Buscar strings hex-like (16, 32, 64 chars) e base64-like
patterns = {
    "hex_16":  re.compile(rb'[0-9a-fA-F]{16}\x00'),
    "hex_32":  re.compile(rb'[0-9a-fA-F]{32}\x00'),
    "hex_64":  re.compile(rb'[0-9a-fA-F]{64}\x00'),
    "base64":  re.compile(rb'[A-Za-z0-9+/]{16,64}={0,2}\x00'),
    "printable_16":  re.compile(rb'[\x20-\x7E]{15,17}\x00'),  # 16 chars como chave TEA
}

for name, pat in patterns.items():
    matches = set()
    for m in pat.finditer(data):
        s = m.group(0)[:-1]
        # Filtros
        if b'.' in s and b' ' in s: continue  # e uma frase
        if s.startswith(b'0000') and s.endswith(b'0000'): continue
        matches.add(s)
    matches_sorted = sorted(matches)[:30]
    if matches_sorted:
        print(f"\n  {name} ({len(matches)} matches unicos, mostrando ate 30):")
        for s in matches_sorted:
            print(f"    {s!r}")

print("\n" + "="*80)
print("FIM V5")
print("="*80)
'@ | Set-Content -Path $scriptPath -Encoding UTF8

Write-Host "`n=== RODANDO V5 ===`n" -ForegroundColor Cyan
python $scriptPath

Stop-Transcript | Out-Null
Write-Host "`n=== Log completo em: $logPath ===" -ForegroundColor Green
