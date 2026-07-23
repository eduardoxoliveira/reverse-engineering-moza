# =============================================================================
# ENGENHARIA REVERSA MOZA — ANALISE V4: FUNCAO COMPLETA + STRINGS REFERENCIADAS
# =============================================================================
#
# CHAVE DA V3:
#   - So o FirmwareManager.exe usa crypt.dll (e nao importa Tea_Decrypt!)
#   - Ele CIFRA os firmwares. O volante descriptografa internamente.
#   - Unico caller de Tea_Init: 0xA31B70
#   - Unico caller de Tea_Encrypt: 0xA31ECA
#   - Tea_Init recebe um std::string (ecx apontando pra local var em ebp-0x80)
#
# V4:
#   1. Desmonta a FUNCAO INTEIRA que contem 0xA31B70 (rastreia prologue/epilogue)
#   2. Lista TODAS as strings referenciadas nessa funcao (push imm32 + lea)
#   3. Analisa methods do std::string local (ebp-0x80)
#   4. Mesma coisa pra funcao que contem 0xA31ECA (Tea_Encrypt)
#   5. Grava output completo em output.txt automaticamente
# =============================================================================

python -m pip install capstone

# Habilitar transcript — grava tudo em output.txt
$logPath = "$env:USERPROFILE\Desktop\moza-re\output_v4.txt"
Start-Transcript -Path $logPath -Force -IncludeInvocationHeader | Out-Null
Write-Host "`n=== Log sendo gravado em: $logPath ===`n"

$scriptPath = "$env:USERPROFILE\Desktop\moza-re\static_v4_function.py"

@'
import struct, re, sys
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

EXE = Path("C:/Program Files (x86)/MOZA Pit House/bin/FirmwareManager.exe")
CALL_SITES = {
    "Tea_Init":    0x00A31B70,
    "Tea_Encrypt": 0x00A31ECA,
}
LOCAL_VAR_STRING = 0x80   # ebp-0x80 = std::string local (visto na V3)

data = EXE.read_bytes()
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

# ============================================================
# PE parsing
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

def va_to_off(va):
    for _, vaddr, vsize, raddr, rsize in sections:
        if vaddr + image_base <= va < vaddr + image_base + vsize:
            return raddr + (va - image_base - vaddr)
    return None

def read_string_at_va(va, max_len=256):
    """Le string ASCII em VA. Retorna None se nao for printavel."""
    off = va_to_off(va)
    if off is None or off >= len(data): return None
    end = data.find(b'\x00', off, off + max_len)
    if end < 0: end = off + max_len
    s = data[off:end]
    if len(s) < 1: return None
    if not all(32 <= b < 127 for b in s): return None
    return s.decode('ascii')

text_sec = next(s for s in sections if s[0] == ".text")
text_va = image_base + text_sec[1]
text_off = text_sec[3]
text_size = text_sec[4]
text_bytes = data[text_off:text_off + text_size]

# ============================================================
# Achar comeco da funcao que contem um endereco
# Padrao MSVC: 55 8B EC (push ebp; mov ebp, esp)
# ============================================================
def find_function_start(va):
    """Busca reversa pelo padrao push ebp; mov ebp, esp."""
    off = va - text_va
    prologue = bytes([0x55, 0x8B, 0xEC])  # push ebp; mov ebp, esp
    prologue2 = bytes([0x55, 0x89, 0xE5])  # variant
    # Buscar reversamente ate 2000 bytes
    for i in range(off, max(0, off - 4000), -1):
        if text_bytes[i:i+3] == prologue or text_bytes[i:i+3] == prologue2:
            return text_va + i
    return None

def disasm_function(start_va, max_bytes=4000):
    """Desmonta ate encontrar ret (C3) ou tamanho maximo."""
    off = start_va - text_va
    end_off = min(off + max_bytes, len(text_bytes))
    code = text_bytes[off:end_off]
    instrs = []
    for ins in md.disasm(code, start_va):
        instrs.append(ins)
        if ins.mnemonic in ("ret", "retn") and len(instrs) > 5:
            break
    return instrs

# ============================================================
# Analisar cada call site
# ============================================================
for func_name, call_va in CALL_SITES.items():
    print(f"\n{'='*80}")
    print(f"# {func_name} @ 0x{call_va:08X}")
    print('='*80)

    start = find_function_start(call_va)
    if not start:
        print(f"  [!] Nao achou inicio da funcao — tentando 200 bytes antes")
        start = call_va - 200
    print(f"  Funcao comeca em: 0x{start:X}")

    instrs = disasm_function(start, max_bytes=6000)
    print(f"  Instrucoes desmontadas: {len(instrs)}")
    print()

    # Coletar todas as strings referenciadas na funcao
    strings_referenced = []
    string_seen = set()
    all_calls_indirect = {}  # addr -> count (funcoes chamadas)

    for ins in instrs:
        # push imm32 (68 XX XX XX XX)
        if ins.mnemonic == "push":
            m = re.match(r'^(0x[0-9a-fA-F]+|-?\d+)$', ins.op_str)
            if m:
                v = int(ins.op_str, 0) & 0xFFFFFFFF
                if v > image_base:
                    s = read_string_at_va(v)
                    if s and s not in string_seen:
                        string_seen.add(s)
                        strings_referenced.append((ins.address, "push", v, s))

        # lea r, [imm32]
        elif ins.mnemonic == "lea":
            m = re.search(r'0x([0-9a-fA-F]+)', ins.op_str)
            if m:
                v = int(m.group(1), 16)
                if v > image_base:
                    s = read_string_at_va(v)
                    if s and s not in string_seen:
                        string_seen.add(s)
                        strings_referenced.append((ins.address, "lea", v, s))

        # mov r, imm32 (b8-bf XX XX XX XX)
        elif ins.mnemonic == "mov":
            m = re.match(r'^(e[abcds][ipx]|e\wi), (0x[0-9a-fA-F]+)$', ins.op_str)
            if m:
                v = int(m.group(2), 16)
                if v > image_base:
                    s = read_string_at_va(v)
                    if s and s not in string_seen:
                        string_seen.add(s)
                        strings_referenced.append((ins.address, "mov", v, s))

        # call dword ptr [imm] (chamada indireta a IAT)
        if ins.mnemonic == "call":
            m = re.search(r'\[0x([0-9a-fA-F]+)\]', ins.op_str)
            if m:
                v = int(m.group(1), 16)
                all_calls_indirect[v] = all_calls_indirect.get(v, 0) + 1

    print(f"--- STRINGS ASCII REFERENCIADAS NA FUNCAO ({len(strings_referenced)}) ---")
    for addr, opt, ptr, s in strings_referenced:
        print(f"  0x{addr:08X}  {opt}  ptr=0x{ptr:X}  {s!r}")

    print(f"\n--- CALLS INDIRETAS (IAT) — funcoes chamadas ({len(all_calls_indirect)}) ---")
    for iat_va, cnt in sorted(all_calls_indirect.items(), key=lambda x: -x[1]):
        print(f"  [0x{iat_va:X}] chamada {cnt}x")

    # ============================================================
    # DISASSEMBLY MARCADO — ao redor do call site (200 antes + 30 depois)
    # ============================================================
    print(f"\n--- DISASSEMBLY MARCADO (200 antes + 30 depois de 0x{call_va:X}) ---")
    for ins in instrs:
        if ins.address < call_va - 250: continue
        if ins.address > call_va + 60: break
        marker = " *** TARGET *** " if ins.address == call_va else "                "
        # Anotar se essa instrucao referencia local var 0x80
        note = ""
        if f"ebp - 0x{LOCAL_VAR_STRING:x}" in ins.op_str.lower():
            note = "  <-- ref [ebp-0x80] (std::string local)"
        if any(s == ins.address for s, _, _, _ in strings_referenced):
            entry = next(x for x in strings_referenced if x[0] == ins.address)
            note = f"  <-- STRING: {entry[3]!r}"
        print(f"  0x{ins.address:08X}: {marker}{ins.mnemonic:<8} {ins.op_str}{note}")

print("\n" + "="*80)
print("FIM DA ANALISE V4")
print("="*80)
print("""
INTERPRETACAO:

Se voce ver algo tipo:
  0x00XXXXXX  push  ptr=0x00YYYYYY  'ALGUMA STRING'
  0x00XXXXXY  lea   ecx, [ebp-0x80]         <-- ref [ebp-0x80]
  0x00XXXXXZ  call  ... (basic_string::assign ou construtor)

Entao ALGUMA STRING e o que vai entrar no std::string que sera passado
pra Tea_Init. Essa e a chave real!

Priorize strings suspeitas: 'Gudsen.88888888', 'Gudsen.888', hex-like,
qualquer coisa que nao seja mensagem de log/erro.
""")
'@ | Set-Content -Path $scriptPath -Encoding UTF8

Write-Host "`n=== RODANDO ANALISE V4 (funcao completa) ===`n" -ForegroundColor Cyan
python $scriptPath

Stop-Transcript | Out-Null
Write-Host "`n=== Log salvo em: $logPath ===" -ForegroundColor Green
