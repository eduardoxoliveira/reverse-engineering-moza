# =============================================================================
# ENGENHARIA REVERSA — MOZA PIT HOUSE / FSR1
# Script executavel — copiar tudo e colar no PowerShell do PC pessoal
# =============================================================================
#
# Pre-requisitos (rodar UMA vez no PC pessoal, na primeira vez):
#
#   winget install --id Python.Python.3.12 --accept-package-agreements --accept-source-agreements --silent
#   python -m pip install lzokay pillow numpy capstone pycryptodome
#
#   $inst = "$env:USERPROFILE\Downloads\python-3.12-x86.exe"
#   Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.12.7/python-3.12.7.exe" -OutFile $inst -UseBasicParsing
#   Start-Process -FilePath $inst -ArgumentList @("/quiet","InstallAllUsers=0","TargetDir=$env:USERPROFILE\Python312-x86","PrependPath=0","Include_launcher=0","Include_test=0","Include_doc=0","Include_pip=1") -Wait
#   & "$env:USERPROFILE\Python312-x86\python.exe" -m pip install lzokay
#
#   New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\Desktop\moza-re" | Out-Null
#   Copy-Item "C:\Program Files (x86)\MOZA Pit House\bin\fmw_bin\4419.bin" "$env:USERPROFILE\Desktop\moza-re\4419_D03_FSR1.bin"
#   Copy-Item "C:\Program Files (x86)\MOZA Pit House\bin\fmw_bin\4516.bin" "$env:USERPROFILE\Desktop\moza-re\4516_W13_FSR2.bin"
#   Copy-Item "C:\Program Files (x86)\MOZA Pit House\bin\crypt.dll"        "$env:USERPROFILE\Desktop\moza-re\crypt.dll"
#
# =============================================================================
# SCRIPT DA VEZ — subprocess isolado + queda de entropia
# =============================================================================

$PY32 = "$env:USERPROFILE\Python312-x86\python.exe"

# WORKER — testa 1 combinacao por processo (imune a segfault)
$worker = "$env:USERPROFILE\Desktop\moza-re\worker.py"
@'
import sys, ctypes, struct, math, json
from ctypes import c_char_p, c_int, create_string_buffer
from pathlib import Path
from collections import Counter

sig_name = sys.argv[1]
key_hex = sys.argv[2]
key_bytes = bytes.fromhex(key_hex)

DLL_PATH = str(Path.home() / "Desktop/moza-re/crypt.dll")
FW = (Path.home() / "Desktop/moza-re/4419_D03_FSR1.bin").read_bytes()
off = 0x20A0 + 1 * 8224
orig = struct.unpack_from("<I", FW, off + 4)[0]
comp = struct.unpack_from("<I", FW, off + 8)[0]
ct = FW[off + 32 : off + 32 + comp]
padded = ct + b'\x00' * ((8 - len(ct) % 8) % 8)

def entropy(d):
    if not d: return 0.0
    c = Counter(d); n = len(d)
    return -sum((v/n) * math.log2(v/n) for v in c.values())

BASE_ENT = entropy(padded)
result = {"sig": sig_name, "key_hex": key_hex, "status": "started"}

try:
    if sig_name.startswith("cdecl"):
        dll = ctypes.CDLL(DLL_PATH)
    else:
        dll = ctypes.WinDLL(DLL_PATH)

    dll.Tea_Init.argtypes = [c_char_p]
    dll.Tea_Init.restype  = c_int
    dll.Tea_Decrypt.argtypes = [c_char_p, c_int]
    dll.Tea_Decrypt.restype  = c_int

    if "_no_init" not in sig_name:
        dll.Tea_Init(key_bytes)

    buf = create_string_buffer(padded, len(padded))

    if "_encrypt" in sig_name:
        dll.Tea_Encrypt.argtypes = [c_char_p, c_int]
        dll.Tea_Encrypt(buf, len(padded))
    else:
        dll.Tea_Decrypt(buf, len(padded))

    plain = bytes(buf.raw[:len(padded)])
    ent = entropy(plain)
    diff = sum(a != b for a, b in zip(padded, plain))

    result.update({
        "status": "ok",
        "entropy_after": round(ent, 3),
        "entropy_drop": round(BASE_ENT - ent, 3),
        "diff_bytes": diff,
        "head_hex": plain[:16].hex(),
    })

    if BASE_ENT - ent > 0.3:
        out = Path.home() / f"Desktop/moza-re/mega/plain_{sig_name}_{key_hex[:20]}.bin"
        out.parent.mkdir(exist_ok=True)
        out.write_bytes(plain)
        result["saved"] = str(out)

except Exception as e:
    result.update({"status": "error", "error": f"{type(e).__name__}: {str(e)[:100]}"})

print(json.dumps(result))
'@ | Set-Content -Path $worker -Encoding UTF8


# ORCHESTRATOR — lanca cada teste isoladamente
$orch = "$env:USERPROFILE\Desktop\moza-re\orchestrator.py"
@'
import subprocess, sys, json
from pathlib import Path

PY32 = str(Path.home() / "Python312-x86/python.exe")
WORKER = str(Path.home() / "Desktop/moza-re/worker.py")

STRINGS = [
    b"Gudsen.88888888",
    b"Gudsen.88888888\x00",
    b"gudsen.88888888",
    b"GUDSEN.88888888",
    b"Gudsen.888888888",
    b"MOZA",
    b"moza",
    b"[RS21-D03-HW_FW-CU-V03][FSR][1][5]",
    b"D03",
    b"FSR",
    b"Gudsen.88888888\n",
    b"Gudsen.88888888\r\n",
    b"Gudsen",
    b"88888888",
    b"password",
]

SIGS = [
    "cdecl_decrypt",
    "cdecl_encrypt",
    "cdecl_no_init_decrypt",
    "stdcall_decrypt",
]

all_results = []
print(f"Testando {len(SIGS) * len(STRINGS)} combinacoes em subprocessos isolados...\n")

for sig in SIGS:
    for s in STRINGS:
        cmd = [PY32, WORKER, sig, s.hex()]
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=15, text=True)
            if r.returncode == 0:
                try:
                    data = json.loads(r.stdout.strip().splitlines()[-1])
                    all_results.append(data)
                    if data.get("status") == "ok":
                        drop = data.get("entropy_drop", 0)
                        head = data.get("head_hex", "")
                        marker = " ***" if drop > 1.0 else ""
                        print(f"  [{sig:<25}] key={s!r:<45} drop={drop:>6.3f} diff={data['diff_bytes']:>4} head={head}{marker}")
                except json.JSONDecodeError:
                    print(f"  [{sig:<25}] key={s!r:<45} bad_json")
            else:
                print(f"  [{sig:<25}] key={s!r:<45} *** CRASH rc={r.returncode} ***")
                all_results.append({"sig": sig, "key_hex": s.hex(), "status": "crash"})
        except subprocess.TimeoutExpired:
            print(f"  [{sig:<25}] key={s!r:<45} TIMEOUT")

outdir = Path.home() / "Desktop/moza-re/mega"
outdir.mkdir(exist_ok=True)
(outdir / "orchestrator_results.json").write_text(json.dumps(all_results, indent=2))

ok = [r for r in all_results if r.get("status") == "ok"]
ok.sort(key=lambda r: r.get("entropy_drop", 0), reverse=True)
print(f"\n=== TOP 10 por queda de entropia ===")
for r in ok[:10]:
    print(f"  drop={r.get('entropy_drop',0):>6.3f} ent_after={r.get('entropy_after',0):>6.3f} "
          f"sig={r['sig']:<25} key={bytes.fromhex(r['key_hex'])!r}")
    print(f"    head: {r.get('head_hex','')}")

best = [r for r in ok if r.get("entropy_drop", 0) > 0.5]
if best:
    import struct as _st
    print(f"\n=== LZO nos {len(best)} candidatos ===")
    for r in best[:5]:
        plain_path = r.get("saved")
        if not plain_path or not Path(plain_path).exists():
            continue
        plain = Path(plain_path).read_bytes()
        try:
            import lzokay
            d = lzokay.decompress(plain[:2227], 8192)
            sp, rv = _st.unpack("<II", d[:8])
            print(f"  [{r['sig']}] LZO OK ({len(d)}b) SP=0x{sp:08X} RV=0x{rv:08X}")
            print(f"    Head: {d[:32].hex(' ').upper()}")
            if 0x08020000 <= rv <= 0x08100000:
                print(f"    *** VETOR STM32 VALIDO ***")
        except Exception as e:
            print(f"  [{r['sig']}] LZO falhou: {type(e).__name__}")
else:
    print("\nNenhum candidato promissor.")
'@ | Set-Content -Path $orch -Encoding UTF8

# EXECUTAR
Write-Host "`n[Executando orchestrador em subprocessos isolados]" -ForegroundColor Cyan
& $PY32 $orch
