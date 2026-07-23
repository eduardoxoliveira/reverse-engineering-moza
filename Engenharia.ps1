# =============================================================================
# ENGENHARIA REVERSA MOZA — V7: FRIDA SPAWN NO FirmwareManager.exe
# =============================================================================
#
# DESCOBERTAS DA V6:
#   - FirmwareManager.exe abre UI COMPLETA quando executado standalone
#   - Detecta o volante FSR1 na COM3 automaticamente
#   - Consulta os servers da Gudsen (backend.gudsen.vip) por updates
#   - Tea_Init nao dispara so por abrir a UI — precisa CLICAR em Update
#   - Qt logging funciona (?info@QMessageLogger produz output em stderr)
#
# ESTRATEGIA V7:
#   Frida SPAWNA o FirmwareManager.exe (nao attach) — hook aplicado ANTES
#   de qualquer codigo rodar. Assim, no primeiro chamada de Tea_Init/Encrypt
#   que ocorrer (mesmo que seja durante uma checagem interna), capturamos.
#
#   Nao precisa fazer flash de verdade — basta a UI abrir e voce interagir.
#   Se ainda nao disparar, podemos apertar botao "Update" e assim que
#   confirmarem, cancelar. Frida ja terá capturado Tea_Init na preparacao.
# =============================================================================

python -m pip install frida-tools

$logPath = "$env:USERPROFILE\Desktop\moza-re\output_v7.txt"
Start-Transcript -Path $logPath -Force -IncludeInvocationHeader | Out-Null
Write-Host "`n=== Log em: $logPath ===`n"


$scriptPath = "$env:USERPROFILE\Desktop\moza-re\hook_spawn.py"

@'
import frida
import sys
import time
import os
from pathlib import Path

FMW = r"C:\Program Files (x86)\MOZA Pit House\bin\FirmwareManager.exe"
WORKING_DIR = r"C:\Program Files (x86)\MOZA Pit House\bin"

JS = r"""
'use strict';

function tryHookCrypt() {
    let mod = null;
    try {
        mod = Process.getModuleByName("crypt.dll");
    } catch (e) {
        return false;
    }
    send({tag: "info", msg: "crypt.dll carregada em " + mod.base});

    const initAddr    = Module.getExportByName("crypt.dll", "Tea_Init");
    const encryptAddr = Module.getExportByName("crypt.dll", "Tea_Encrypt");
    const decryptAddr = Module.getExportByName("crypt.dll", "Tea_Decrypt");

    Interceptor.attach(initAddr, {
        onEnter(args) {
            const p = args[0];
            let info = {tag: "TEA_INIT", ptr: p.toString()};
            if (!p.isNull()) {
                try { info.string = p.readCString(); } catch (e) {}
                try {
                    const b = p.readByteArray(128);
                    info.bytes_hex = Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2,"0")).join(" ");
                } catch (e) {}
            }
            send(info);
        },
        onLeave(retval) {
            let info = {tag: "TEA_INIT_DONE", retval: retval.toString()};
            try {
                const base = Process.getModuleByName("crypt.dll").base;
                const key = base.add(0x43D4).readByteArray(16);
                info.key_hex = Array.from(new Uint8Array(key)).map(x => x.toString(16).padStart(2,"0")).join(" ");
            } catch (e) { info.err = String(e); }
            send(info);
        }
    });

    Interceptor.attach(decryptAddr, {
        onEnter(args) {
            this.buf = args[0]; this.len = args[1].toInt32();
            let info = {tag: "TEA_DECRYPT_IN", len: this.len};
            try {
                const b = this.buf.readByteArray(Math.min(48, this.len));
                info.cipher_head = Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2,"0")).join(" ");
            } catch (e) {}
            send(info);
        },
        onLeave() {
            let info = {tag: "TEA_DECRYPT_OUT"};
            try {
                const b = this.buf.readByteArray(Math.min(48, this.len));
                info.plain_head = Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2,"0")).join(" ");
            } catch (e) {}
            send(info);
        }
    });

    Interceptor.attach(encryptAddr, {
        onEnter(args) {
            this.buf = args[0]; this.len = args[1].toInt32();
            let info = {tag: "TEA_ENCRYPT_IN", len: this.len};
            try {
                const b = this.buf.readByteArray(Math.min(48, this.len));
                info.plain_head = Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2,"0")).join(" ");
            } catch (e) {}
            send(info);
        },
        onLeave() {
            let info = {tag: "TEA_ENCRYPT_OUT"};
            try {
                const b = this.buf.readByteArray(Math.min(48, this.len));
                info.cipher_head = Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2,"0")).join(" ");
            } catch (e) {}
            send(info);
        }
    });

    return true;
}

// Watch LoadLibrary — crypt.dll pode ser carregada lazy
["LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW"].forEach(name => {
    try {
        const addr = Module.getExportByName("kernel32.dll", name);
        Interceptor.attach(addr, {
            onLeave() {
                if (tryHookCrypt()) {
                    // Sucesso, remove watch se possivel
                }
            }
        });
    } catch (e) {}
});

// Watch CreateFile pra ver o que o FirmwareManager le
["CreateFileA", "CreateFileW"].forEach(name => {
    try {
        const addr = Module.getExportByName("kernel32.dll", name);
        Interceptor.attach(addr, {
            onEnter(args) {
                try {
                    let s = name.endsWith("W") ? args[0].readUtf16String() : args[0].readCString();
                    if (s && (s.toLowerCase().includes(".bin") || s.toLowerCase().includes("fmw") || s.toLowerCase().includes("firmware"))) {
                        send({tag: "FILE_OPEN", path: s});
                    }
                } catch (e) {}
            }
        });
    } catch (e) {}
});

// Tentar hook inicial (caso crypt.dll ja esteja carregada por linker)
tryHookCrypt();
send({tag: "info", msg: "hooks instalados, aguardando calls..."});
"""

def on_message(msg, data):
    if msg["type"] == "error":
        print("[FRIDA ERROR]", msg.get("stack", msg), flush=True)
        return
    p = msg.get("payload", {})
    tag = p.get("tag", "?")
    if tag == "info":
        print(f"  [info] {p.get('msg')}", flush=True)
    elif tag == "TEA_INIT":
        print("\n" + "*"*60, flush=True)
        print(f"*** TEA_INIT CHAMADO ***", flush=True)
        print(f"  ptr: {p.get('ptr')}", flush=True)
        print(f"  como string: {p.get('string')!r}", flush=True)
        print(f"  128 bytes hex: {p.get('bytes_hex')}", flush=True)
    elif tag == "TEA_INIT_DONE":
        print(f"  Retorno: {p.get('retval')}", flush=True)
        print(f"  CHAVE GERADA (16 bytes): {p.get('key_hex')}", flush=True)
        print("*"*60 + "\n", flush=True)
    elif tag == "TEA_ENCRYPT_IN":
        print(f"\n[Tea_Encrypt IN] len={p.get('len')}", flush=True)
        print(f"  plain head: {p.get('plain_head')}", flush=True)
    elif tag == "TEA_ENCRYPT_OUT":
        print(f"[Tea_Encrypt OUT]", flush=True)
        print(f"  cipher head: {p.get('cipher_head')}", flush=True)
    elif tag == "TEA_DECRYPT_IN":
        print(f"\n[Tea_Decrypt IN] len={p.get('len')}", flush=True)
    elif tag == "TEA_DECRYPT_OUT":
        print(f"[Tea_Decrypt OUT] plain head: {p.get('plain_head')}", flush=True)
    elif tag == "FILE_OPEN":
        print(f"  [FILE] {p.get('path')}", flush=True)
    else:
        print(f"  [?] {p}", flush=True)

def main():
    device = frida.get_local_device()
    print(f"Spawning FirmwareManager.exe com Frida hook desde boot...", flush=True)

    # Setar env vars antes do spawn
    os.environ["QT_LOGGING_RULES"] = "*=true"
    os.environ["QT_FORCE_STDERR_LOGGING"] = "1"

    try:
        pid = device.spawn([FMW])
        print(f"  PID: {pid}", flush=True)
        session = device.attach(pid)
        script = session.create_script(JS)
        script.on("message", on_message)
        script.load()
        device.resume(pid)
        print(f"  Resumido. Hooks ativos.", flush=True)
    except Exception as e:
        print(f"[!] Erro no spawn: {e}", flush=True)
        return 1

    print("""
=====================================================
UI DO FirmwareManager SUBIU. HOOKS ATIVOS EM crypt.dll
=====================================================
- Aguardando Tea_Init/Tea_Encrypt/Tea_Decrypt disparar
- Interaja com a UI: selecione volante, clique em botoes de firmware
- Se aparecer botao "Update" ou "Verify", clique — pode disparar Tea_Init
- SE APARECER TELA DE CONFIRMACAO DE FLASH, CANCELE (nao precisa flashear)

Ctrl+C aqui pra encerrar apos capturar o que precisa.
""", flush=True)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[detach]", flush=True)
        try: session.detach()
        except: pass
    return 0

if __name__ == "__main__":
    sys.exit(main())
'@ | Set-Content -Path $scriptPath -Encoding UTF8

Write-Host "`n=== RODANDO V7 (Frida spawn) ===" -ForegroundColor Cyan
python $scriptPath

Stop-Transcript | Out-Null
Write-Host "`n=== Log em: $logPath ===" -ForegroundColor Green
