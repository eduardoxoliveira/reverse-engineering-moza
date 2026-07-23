# =============================================================================
# ENGENHARIA REVERSA MOZA — V9: FIX Frida API (Module.getExportByName removido)
# =============================================================================
#
# CONFIRMADO NA V7:
#   - UI abriu ✓
#   - Ao clicar 'Instalar Firmware' o pipeline dispara Tea_Init
#   - MAS: TypeError na linha 13: Module.getExportByName nao existe mais
#
# CAUSA:
#   Frida 17+ removeu Module.getExportByName. Precisamos usar:
#     Module.load("crypt.dll").findExportByName("Tea_Init")
#   OU
#     Process.getModuleByName("crypt.dll").findExportByName("Tea_Init")
#   OU
#     Process.getModuleByName("crypt.dll").enumerateExports()
#
# V9:
#   1. Reimplementa hook com API compativel (usa enumerateExports)
#   2. Mantem watchers LoadLibrary/CreateFile
#   3. Mesmo passo-a-passo: spawnar FirmwareManager, interagir, cancelar
# =============================================================================

python -m pip install frida-tools

$logPath = "$env:USERPROFILE\Desktop\moza-re\output_v9.txt"
Start-Transcript -Path $logPath -Force -IncludeInvocationHeader | Out-Null

$env:QT_LOGGING_RULES = "*=true"
$env:QT_FORCE_STDERR_LOGGING = "1"

$scriptPath = "$env:USERPROFILE\Desktop\moza-re\hook_v9.py"

@'
import frida, sys, time, os
from pathlib import Path

FMW = r"C:\Program Files (x86)\MOZA Pit House\bin\FirmwareManager.exe"

JS = r"""
'use strict';

let hooked = false;

function findExport(modName, symName) {
    // Tentar API nova (Frida 17+)
    try {
        const mod = Process.getModuleByName(modName);
        if (mod.findExportByName) {
            const addr = mod.findExportByName(symName);
            if (addr) return addr;
        }
    } catch (e) {}
    // Tentar enumerar exports manualmente
    try {
        const mod = Process.getModuleByName(modName);
        const exps = mod.enumerateExports();
        for (const e of exps) {
            if (e.name === symName) return e.address;
        }
    } catch (e) {}
    // Fallback: API antiga
    try {
        return Module.findExportByName(modName, symName);
    } catch (e) {}
    return null;
}

function tryHookCrypt() {
    if (hooked) return true;
    let mod = null;
    try {
        mod = Process.getModuleByName("crypt.dll");
    } catch (e) {
        return false;
    }
    send({tag: "info", msg: "crypt.dll carregada em " + mod.base + " size=" + mod.size});

    const initAddr    = findExport("crypt.dll", "Tea_Init");
    const encryptAddr = findExport("crypt.dll", "Tea_Encrypt");
    const decryptAddr = findExport("crypt.dll", "Tea_Decrypt");

    send({tag: "info", msg: "Tea_Init addr: " + initAddr});
    send({tag: "info", msg: "Tea_Encrypt addr: " + encryptAddr});
    send({tag: "info", msg: "Tea_Decrypt addr: " + decryptAddr});

    if (!initAddr) {
        send({tag: "info", msg: "*** ERRO: nao encontrou exports. Listando ates 20 ***"});
        try {
            const exps = mod.enumerateExports();
            for (let i = 0; i < Math.min(20, exps.length); i++) {
                send({tag: "info", msg: "  export: " + exps[i].name + " @ " + exps[i].address});
            }
        } catch (e) { send({tag: "info", msg: "enum falhou: " + e}); }
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

    hooked = true;
    send({tag: "info", msg: "HOOKS APLICADOS COM SUCESSO"});
    return true;
}

// Watch LoadLibrary — crypt.dll pode ser lazy
["LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW"].forEach(name => {
    try {
        const addr = findExport("kernel32.dll", name);
        if (addr) {
            Interceptor.attach(addr, {
                onLeave() {
                    tryHookCrypt();
                }
            });
        }
    } catch (e) {}
});

// Watch CreateFile
["CreateFileA", "CreateFileW"].forEach(name => {
    try {
        const addr = findExport("kernel32.dll", name);
        if (addr) {
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
        }
    } catch (e) {}
});

// Tentar hook imediato
tryHookCrypt();
send({tag: "info", msg: "V9 watchers instalados"});
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
        print(f"  *** CHAVE GERADA (16 bytes): {p.get('key_hex')} ***", flush=True)
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
        print(f"[Tea_Decrypt OUT] plain: {p.get('plain_head')}", flush=True)
    elif tag == "FILE_OPEN":
        print(f"  [FILE] {p.get('path')}", flush=True)
    else:
        print(f"  [?] {p}", flush=True)

def main():
    device = frida.get_local_device()
    print(f"Frida version: {frida.__version__}", flush=True)
    print(f"Spawning FirmwareManager.exe...", flush=True)

    try:
        pid = device.spawn([FMW])
        print(f"  PID: {pid}", flush=True)
        session = device.attach(pid)
        script = session.create_script(JS)
        script.on("message", on_message)
        script.load()
        device.resume(pid)
        print(f"  UI subindo. Hooks instalados.", flush=True)
    except Exception as e:
        print(f"[!] Erro no spawn: {e}", flush=True)
        return 1

    print("""
=====================================================
UI DEVE ABRIR. HOOKS ATIVOS.
=====================================================
Aguarde ate ver 'HOOKS APLICADOS COM SUCESSO' no console.

Depois:
- Selecione o volante FSR1
- Clique em 'Update Firmware' ou 'Verificar'
- Se aparecer versao disponivel, clique em INSTALAR
- Quando aparecer tela de CONFIRMACAO / progresso, cancele
- Tea_Init deve ter sido chamada na preparacao — chave estara acima

Ctrl+C aqui pra encerrar.
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

Write-Host "`n=== RODANDO V9 (API Frida corrigida) ===" -ForegroundColor Cyan
python $scriptPath

Stop-Transcript | Out-Null

Remove-Item Env:QT_LOGGING_RULES -ErrorAction SilentlyContinue
Remove-Item Env:QT_FORCE_STDERR_LOGGING -ErrorAction SilentlyContinue

Write-Host "`n=== Log em: $logPath ===" -ForegroundColor Green
