# =============================================================================
# ENGENHARIA REVERSA MOZA — ANALISE V6: Qt LOGGING + FUNCAO REAL DO THUNK
# =============================================================================
#
# DESCOBERTA-CHAVE V5:
#   O FirmwareManager tem uma linha de LOG:
#     QMessageLogger::info("Tea_Init key: ") << key_qstring
#
#   Isso e ?info@QMessageLogger@@... — o Qt debug logger. Se ativarmos
#   QT_LOGGING_RULES=*=true, essa mensagem pode aparecer no stderr do
#   processo — imprimindo a chave literal!
#
# ESTRATEGIA V6:
#   1. Rodar FirmwareManager.exe standalone com QT_LOGGING_RULES ativo
#      e capturar stderr
#   2. Se ele nao aceita args, testar variacoes de CLI
#   3. Tambem: procurar 0xA31750 em .data/.rdata (vtables)
#   4. Analisar a funcao REAL pra onde 0x401992 pula (0x494D20)
# =============================================================================

# Start-Transcript
$logPath = "$env:USERPROFILE\Desktop\moza-re\output_v6.txt"
Start-Transcript -Path $logPath -Force -IncludeInvocationHeader | Out-Null

Write-Host "`n=== V6-A: RODANDO FirmwareManager.exe COM Qt LOGGING ===" -ForegroundColor Cyan
Write-Host "Se aparecer 'Tea_Init key:' seguido de bytes, ACHAMOS A CHAVE!`n"

$fmw = "C:\Program Files (x86)\MOZA Pit House\bin\FirmwareManager.exe"

# Configurar logging Qt via env var e QT_MESSAGE_PATTERN
$env:QT_LOGGING_RULES = "*=true"
$env:QT_MESSAGE_PATTERN = "[%{type}] %{message}"
$env:QT_FORCE_STDERR_LOGGING = "1"

# Testar varios modos de invocacao — capturando stderr+stdout
Write-Host "--- Teste 1: sem args ---" -ForegroundColor Yellow
$out1 = & $fmw 2>&1 | Out-String
Write-Host $out1
Write-Host "Exit code: $LASTEXITCODE`n"

Write-Host "--- Teste 2: --help ---" -ForegroundColor Yellow
$out2 = & $fmw --help 2>&1 | Out-String
Write-Host $out2
Write-Host "Exit code: $LASTEXITCODE`n"

Write-Host "--- Teste 3: -h ---" -ForegroundColor Yellow
$out3 = & $fmw -h 2>&1 | Out-String
Write-Host $out3
Write-Host "Exit code: $LASTEXITCODE`n"

Write-Host "--- Teste 4: /? ---" -ForegroundColor Yellow
$out4 = & $fmw /? 2>&1 | Out-String
Write-Host $out4
Write-Host "Exit code: $LASTEXITCODE`n"

# Se apareceu algo com "Tea_Init" em qualquer output, destacar
foreach ($out in @($out1, $out2, $out3, $out4)) {
    if ($out -match "(?im)Tea_Init") {
        Write-Host "*** 'Tea_Init' APARECEU no output! ***" -ForegroundColor Green
        Write-Host $out
    }
}


# =============================================================================
Write-Host "`n=== V6-B: ANALISE COMPLEMENTAR NO BINARIO ===" -ForegroundColor Cyan

$scriptPath = "$env:USERPROFILE\Desktop\moza-re\static_v6.py"

@'
import struct, re
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

EXE = Path("C:/Program Files (x86)/MOZA Pit House/bin/FirmwareManager.exe")
data = EXE.read_bytes()
md = Cs(CS_ARCH_X86, CS_MODE_32)

# PE
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

# --- 1) Analisar a funcao REAL apontada por 0x401992 (primeiro jmp = 0x494D20)
print("="*80)
print("1) FUNCAO REAL 0x494D20 (pra onde 0x401992 salta)")
print("="*80)
text_sec = next(s for s in sections if s[0] == ".text")
text_va = image_base + text_sec[1]
text_bytes = data[text_sec[3]:text_sec[3] + text_sec[4]]
off = 0x494D20 - text_va
code = text_bytes[off:off + 2000]
count = 0
for ins in md.disasm(code, 0x494D20):
    op_str = ins.op_str
    # push imm32 -> string
    if ins.mnemonic == "push":
        m = re.match(r'^(0x[0-9a-fA-F]+)$', op_str)
        if m:
            v = int(m.group(1), 16)
            if v > image_base:
                o = va_to_off(v)
                if o:
                    end = data.find(b'\x00', o, o + 200)
                    if end > o:
                        s = data[o:end]
                        if 1 < len(s) < 100 and all(32 <= b < 127 for b in s):
                            op_str += f"  ; '{s.decode('ascii')}'"
    print(f"  0x{ins.address:08X}: {ins.mnemonic:<8} {op_str}")
    count += 1
    if ins.mnemonic in ("ret", "retn") or count > 40: break

# --- 2) Buscar referencias ao endereco 0xA31750 no binario (vtables, etc)
print("\n" + "="*80)
print("2) REFERENCIAS AO ENDERECO 0xA31750 NO BINARIO INTEIRO")
print("="*80)
needle = struct.pack("<I", 0xA31750)
positions = []
pos = 0
while True:
    pos = data.find(needle, pos)
    if pos < 0: break
    positions.append(pos)
    pos += 1

print(f"Encontradas {len(positions)} referencias:")
for p in positions[:30]:
    # Determinar em qual secao esta
    section_name = "?"
    for name, vaddr, vsize, raddr, rsize in sections:
        if raddr <= p < raddr + rsize:
            section_name = name
            break
    va = None
    for name, vaddr, vsize, raddr, rsize in sections:
        if raddr <= p < raddr + rsize:
            va = image_base + vaddr + (p - raddr)
            break
    print(f"  file 0x{p:X} VA 0x{va:X}  section {section_name}")
    # Se em .rdata, provavelmente vtable — imprimir 4 dwords vizinhos
    if section_name in (".rdata", ".data"):
        neighbors = struct.unpack_from("<4I", data, max(0, p - 8))
        print(f"    vtable-like: {[hex(x) for x in neighbors]}")

# --- 3) Buscar por _guard_check_icall padrao (call reg) que ponha 0xA31750
print("\n" + "="*80)
print("3) INSTRUCOES 'mov reg, 0xA31750' (carregar endereco)")
print("="*80)
# mov r32, imm32:  B8-BF XX XX XX XX  (B8=eax B9=ecx BA=edx BB=ebx BC=esp BD=ebp BE=esi BF=edi)
addr_le = struct.pack("<I", 0xA31750)
for opc in range(0xB8, 0xC0):
    needle2 = bytes([opc]) + addr_le
    positions2 = []
    pos = 0
    while True:
        pos = text_bytes.find(needle2, pos)
        if pos < 0: break
        positions2.append(pos)
        pos += 1
    reg = ["eax","ecx","edx","ebx","esp","ebp","esi","edi"][opc - 0xB8]
    if positions2:
        for p in positions2[:5]:
            va = text_va + p
            print(f"  mov {reg}, 0xA31750 @ VA 0x{va:X}")

# push imm32 0xA31750
needle3 = bytes([0x68]) + addr_le
positions3 = []
pos = 0
while True:
    pos = text_bytes.find(needle3, pos)
    if pos < 0: break
    positions3.append(pos)
    pos += 1
for p in positions3[:5]:
    va = text_va + p
    print(f"  push 0xA31750 @ VA 0x{va:X}")

# Nao encontrado? Talvez seja em vtable no .rdata
'@ | Set-Content -Path $scriptPath -Encoding UTF8

python $scriptPath

Stop-Transcript | Out-Null
Write-Host "`n=== Log completo em: $logPath ===" -ForegroundColor Green

# Limpar env vars
Remove-Item Env:QT_LOGGING_RULES -ErrorAction SilentlyContinue
Remove-Item Env:QT_MESSAGE_PATTERN -ErrorAction SilentlyContinue
Remove-Item Env:QT_FORCE_STDERR_LOGGING -ErrorAction SilentlyContinue
