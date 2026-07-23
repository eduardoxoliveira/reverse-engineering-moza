# =============================================================================
# ENGENHARIA REVERSA MOZA — V10: Frida hook + gravacao direto no Python
# =============================================================================
#
# PROBLEMA V9:
#   Start-Transcript do PowerShell nao captura stdout do Python subprocess.
#   Log ficou quase vazio.
#
# V10:
#   - Python grava output diretamente com open("output.txt", "a")
#   - Cada mensagem vai pra tela E pro arquivo
#   - Nao depende do Start-Transcript
# =============================================================================

python -m pip install frida-tools

$env:QT_LOGGING_RULES = "*=true"
$env:QT_FORCE_STDERR_LOGGING = "1"

$scriptPath = "$env:USERPROFILE\Desktop\moza-re\hook_v10.py"

@'
import frida, sys, time, os
from pathlib import Path
from datetime import datetime

FMW = r"C:\Program Files (x86)\MOZA Pit House\bin\FirmwareManager.exe"
LOG = Path.home() / "Desktop/moza-re/output_v10.txt"

# Abrir log em modo append + line-buffered
LOG.parent.mkdir(exist_ok=True)
LOG_F = open(LOG, "w", encoding="utf-8", buffering=1)

def log(msg):
    line = f"{datetime.now().strftime('%H:%M:%S.%f')[:-3]}  {msg}"
    print(line, flush=True)
    LOG_F.write(line + "\n")
    LOG_F.flush()

JS = r"""
'use strict';
let hooked = false;

function findExport(modName, symName) {
    try {
        const mod = Process.getModuleByName(modName);
        if (mod.findExportByName) {
            const addr = mod.findExportByName(symName);
            if (addr) return addr;
        }
    } catch (e) {}
    try {
        const mod = Process.getModuleByName(modName);
        const exps = mod.enumerateExports();
        for (const e of exps) {
            if (e.name === symName) return e.address;
        }
    } catch (e) {}
    try { return Module.findExportByName(modName, symName); } catch (e) {}
    return null;
}

function tryHookCrypt() {
    if (hooked) return true;
    let mod = null;
    try { mod = Process.getModuleByName("crypt.dll"); }
    catch (e) { return false; }

    send({tag: "info", msg: "crypt.dll @ " + mod.base + " size=" + mod.size});

    const initAddr = findExport("crypt.dll", "Tea_Init");
    const encAddr  = findExport("crypt.dll", "Tea_Encrypt");
    const decAddr  = findExport("crypt.dll", "Tea_Decrypt");

    send({tag: "info", msg: "Tea_Init=" + initAddr + " Tea_Encrypt=" + encAddr + " Tea_Decrypt=" + decAddr});

    if (!initAddr) {
        send({tag: "info", msg: "*** ERRO: exports nao encontrados. Listando ate 30 ***"});
        try {
            const exps = mod.enumerateExports();
            for (let i = 0; i < Math.min(30, exps.length); i++) {
                send({tag: "info", msg: "  export[" + i + "]: " + exps[i].name});
            }
        } catch (e) { send({tag: "info", msg: "enum failed: " + e}); }
        return false;
    }

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
                const key = Process.getModuleByName("crypt.dll").base.add(0x43D4).readByteArray(16);
                info.key_hex = Array.from(new Uint8Array(key)).map(x => x.toString(16).padStart(2,"0")).join(" ");
            } catch (e) { info.err = String(e); }
            send(info);
        }
    });

    Interceptor.attach(decAddr, {
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

    Interceptor.attach(encAddr, {
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

    hooked = true;
    send({tag: "info", msg: "HOOKS APLICADOS COM SUCESSO"});
    return true;
}

["LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW"].forEach(name => {
    try {
        const addr = findExport("kernel32.dll", name);
        if (addr) Interceptor.attach(addr, { onLeave() { tryHookCrypt(); } });
    } catch (e) {}
});

["CreateFileA", "CreateFileW"].forEach(name => {
    try {
        const addr = findExport("kernel32.dll", name);
        if (addr) Interceptor.attach(addr, {
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

tryHookCrypt();
send({tag: "info", msg: "V10 watchers instalados"});
"""

def on_message(msg, data):
    if msg["type"] == "error":
        log(f"[FRIDA ERROR] {msg.get('stack', msg)}")
        return
    p = msg.get("payload", {})
    tag = p.get("tag", "?")
    if tag == "info":
        log(f"  [info] {p.get('msg')}")
    elif tag == "TEA_INIT":
        log("")
        log("*"*60)
        log("*** TEA_INIT CHAMADO ***")
        log(f"  ptr: {p.get('ptr')}")
        log(f"  como string: {p.get('string')!r}")
        log(f"  128 bytes hex: {p.get('bytes_hex')}")
    elif tag == "TEA_INIT_DONE":
        log(f"  Retorno: {p.get('retval')}")
        log(f"  *** CHAVE GERADA (16 bytes): {p.get('key_hex')} ***")
        log("*"*60)
        log("")
    elif tag == "TEA_ENCRYPT_IN":
        log(f"[Tea_Encrypt IN] len={p.get('len')} plain head: {p.get('plain_head')}")
    elif tag == "TEA_ENCRYPT_OUT":
        log(f"[Tea_Encrypt OUT] cipher head: {p.get('cipher_head')}")
    elif tag == "TEA_DECRYPT_IN":
        log(f"[Tea_Decrypt IN] len={p.get('len')} cipher: {p.get('cipher_head')}")
    elif tag == "TEA_DECRYPT_OUT":
        log(f"[Tea_Decrypt OUT] plain head: {p.get('plain_head')}")
    elif tag == "FILE_OPEN":
        log(f"  [FILE] {p.get('path')}")
    else:
        log(f"  [?] {p}")

def main():
    log(f"=== V10 HOOK — {datetime.now()} ===")
    log(f"Frida: {frida.__version__}")
    log(f"Python: {sys.version.split()[0]} ({8 * (1 if sys.maxsize > 2**32 else 0) + 32}-bit)")

    device = frida.get_local_device()
    log(f"Device: {device.name}")

    try:
        pid = device.spawn([FMW])
        log(f"Spawn PID: {pid}")
        session = device.attach(pid)
        script = session.create_script(JS)
        script.on("message", on_message)
        script.load()
        log("Script loaded")
        device.resume(pid)
        log("Process resumed — UI deve subir agora")
    except Exception as e:
        log(f"[!] Erro no spawn: {type(e).__name__}: {e}")
        LOG_F.close()
        return 1

    log("")
    log("="*60)
    log("AGORA NO PROGRAMA:")
    log("  1. Aguarde 'HOOKS APLICADOS COM SUCESSO' aparecer")
    log("  2. Selecione o volante FSR1")
    log("  3. Clique em 'Update Firmware' / 'Instalar'")
    log("  4. Cancele quando pedir confirmacao")
    log("  5. Tea_Init sera capturado aqui")
    log("  6. Ctrl+C para encerrar")
    log("="*60)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log("\n[detach] encerrando...")
        try: session.detach()
        except: pass
    LOG_F.close()
    return 0

if __name__ == "__main__":
    sys.exit(main())
'@ | Set-Content -Path $scriptPath -Encoding UTF8

Write-Host "`n=== RODANDO V10 ===" -ForegroundColor Cyan
Write-Host "Log em: $env:USERPROFILE\Desktop\moza-re\output_v10.txt" -ForegroundColor Yellow
Write-Host ""
python $scriptPath

Remove-Item Env:QT_LOGGING_RULES -ErrorAction SilentlyContinue
Remove-Item Env:QT_FORCE_STDERR_LOGGING -ErrorAction SilentlyContinue

Write-Host "`n=== Log gravado em: $env:USERPROFILE\Desktop\moza-re\output_v10.txt ===" -ForegroundColor Green
