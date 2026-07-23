# =============================================================================
# ENGENHARIA REVERSA MOZA — V11: RESOLVER CONFLITO crypt.dll (sistema vs Moza)
# =============================================================================
#
# DESCOBERTA V10:
#   O hook foi aplicado numa crypt.dll de 28KB, MAS o Moza crypt.dll tem 11KB.
#   Estamos hookando a DLL ERRADA! Windows carregou outra crypt.dll com o
#   mesmo nome mas conteudo diferente.
#
# V11:
#   1. Enumera TODOS os modulos carregados no FirmwareManager.exe
#   2. Imprime path completo + tamanho de cada
#   3. Busca 'crypt' no nome em qualquer variacao
#   4. Busca exports 'Tea_' em TODOS os modulos (nao so crypt.dll)
#   5. Hookea onde efetivamente encontrar
# =============================================================================

python -m pip install frida-tools

$env:QT_LOGGING_RULES = "*=true"
$env:QT_FORCE_STDERR_LOGGING = "1"

$scriptPath = "$env:USERPROFILE\Desktop\moza-re\hook_v11.py"

@'
import frida, sys, time
from pathlib import Path
from datetime import datetime

FMW = r"C:\Program Files (x86)\MOZA Pit House\bin\FirmwareManager.exe"
LOG = Path.home() / "Desktop/moza-re/output_v11.txt"
LOG_F = open(LOG, "w", encoding="utf-8", buffering=1)

def log(msg):
    line = f"{datetime.now().strftime('%H:%M:%S.%f')[:-3]}  {msg}"
    print(line, flush=True)
    LOG_F.write(line + "\n")
    LOG_F.flush()

JS = r"""
'use strict';

function scanModulesAndHook() {
    send({tag: "info", msg: "=== MODULOS CARREGADOS ==="});
    const mods = Process.enumerateModules();
    send({tag: "info", msg: "Total: " + mods.length + " modulos"});

    let cryptCandidates = [];
    let teaFunctions = [];

    for (const m of mods) {
        // Log modulos que tem 'crypt' no nome ou path
        if (m.name.toLowerCase().includes("crypt") ||
            m.path.toLowerCase().includes("crypt")) {
            send({tag: "mod", name: m.name, path: m.path, base: m.base.toString(), size: m.size});
            cryptCandidates.push(m);
        }

        // Buscar exports Tea_ em TODOS os modulos
        try {
            const exps = m.enumerateExports();
            for (const e of exps) {
                if (e.name.startsWith("Tea_") || e.name.toLowerCase().includes("tea_init") ||
                    e.name.toLowerCase().includes("tea_encrypt") || e.name.toLowerCase().includes("tea_decrypt")) {
                    send({tag: "tea_export", module: m.name, path: m.path, name: e.name, address: e.address.toString()});
                    teaFunctions.push({mod: m, addr: e.address, name: e.name});
                }
            }
        } catch (e) {}
    }

    send({tag: "info", msg: "Candidatos crypt: " + cryptCandidates.length});
    send({tag: "info", msg: "Funcoes Tea_ encontradas: " + teaFunctions.length});

    // Hookar TODAS Tea_ encontradas
    for (const t of teaFunctions) {
        const name = t.name;
        send({tag: "info", msg: "Instalando hook em " + name + " @ " + t.addr + " (mod: " + t.mod.name + ")"});

        if (name === "Tea_Init") {
            Interceptor.attach(t.addr, {
                onEnter(args) {
                    const p = args[0];
                    let info = {tag: "TEA_INIT", mod: t.mod.name, ptr: p.toString()};
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
                        const key = t.mod.base.add(0x43D4).readByteArray(16);
                        info.key_hex = Array.from(new Uint8Array(key)).map(x => x.toString(16).padStart(2,"0")).join(" ");
                    } catch (e) { info.err = String(e); }
                    send(info);
                }
            });
        } else if (name === "Tea_Encrypt") {
            Interceptor.attach(t.addr, {
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
        } else if (name === "Tea_Decrypt") {
            Interceptor.attach(t.addr, {
                onEnter(args) {
                    this.buf = args[0]; this.len = args[1].toInt32();
                    send({tag: "TEA_DECRYPT_IN", len: this.len});
                }
            });
        }
    }
    return teaFunctions.length > 0;
}

// Rodar scan quando Qt terminar de carregar (~2s depois)
setTimeout(() => scanModulesAndHook(), 500);
setTimeout(() => scanModulesAndHook(), 2000);
setTimeout(() => scanModulesAndHook(), 5000);

// LoadLibrary watcher — captura qualquer crypt sendo carregada
["LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW"].forEach(name => {
    try {
        const mod = Process.getModuleByName("kernel32.dll");
        const addr = mod.findExportByName ? mod.findExportByName(name) : null;
        if (addr) {
            Interceptor.attach(addr, {
                onEnter(args) {
                    try {
                        let s = name.endsWith("W") ? args[0].readUtf16String() : args[0].readCString();
                        if (s && s.toLowerCase().includes("crypt")) {
                            send({tag: "info", msg: name + "(" + s + ")"});
                        }
                    } catch (e) {}
                },
                onLeave() {
                    setTimeout(() => scanModulesAndHook(), 100);
                }
            });
        }
    } catch (e) {}
});

// CreateFile watcher — arquivos de firmware
["CreateFileA", "CreateFileW"].forEach(name => {
    try {
        const mod = Process.getModuleByName("kernel32.dll");
        const addr = mod.findExportByName ? mod.findExportByName(name) : null;
        if (addr) Interceptor.attach(addr, {
            onEnter(args) {
                try {
                    let s = name.endsWith("W") ? args[0].readUtf16String() : args[0].readCString();
                    if (s && (s.toLowerCase().includes("fmw_bin") ||
                              s.toLowerCase().includes("firmware") ||
                              s.toLowerCase().includes("moza"))) {
                        send({tag: "FILE_OPEN", path: s});
                    }
                } catch (e) {}
            }
        });
    } catch (e) {}
});
"""

def on_message(msg, data):
    if msg["type"] == "error":
        log(f"[FRIDA ERROR] {msg.get('stack', msg)}")
        return
    p = msg.get("payload", {})
    tag = p.get("tag", "?")
    if tag == "info":
        log(f"  [info] {p.get('msg')}")
    elif tag == "mod":
        log(f"  [MOD crypt-like] name={p.get('name')} base={p.get('base')} size={p.get('size')}")
        log(f"                    path={p.get('path')}")
    elif tag == "tea_export":
        log(f"  [TEA EXPORT] name={p.get('name')} module={p.get('module')} addr={p.get('address')}")
        log(f"                path={p.get('path')}")
    elif tag == "TEA_INIT":
        log("")
        log("*"*60)
        log(f"*** TEA_INIT CHAMADO (mod={p.get('mod')}) ***")
        log(f"  ptr: {p.get('ptr')}")
        log(f"  como string: {p.get('string')!r}")
        log(f"  128 bytes hex: {p.get('bytes_hex')}")
    elif tag == "TEA_INIT_DONE":
        log(f"  Retorno: {p.get('retval')}")
        log(f"  *** CHAVE GERADA (16 bytes): {p.get('key_hex')} ***")
        log("*"*60)
    elif tag == "TEA_ENCRYPT_IN":
        log(f"[Tea_Encrypt IN] len={p.get('len')} plain: {p.get('plain_head')}")
    elif tag == "TEA_ENCRYPT_OUT":
        log(f"[Tea_Encrypt OUT] cipher: {p.get('cipher_head')}")
    elif tag == "TEA_DECRYPT_IN":
        log(f"[Tea_Decrypt IN] len={p.get('len')}")
    elif tag == "FILE_OPEN":
        log(f"  [FILE] {p.get('path')}")
    else:
        log(f"  [?] {p}")

def main():
    log(f"=== V11 HOOK — {datetime.now()} ===")
    log(f"Frida: {frida.__version__}")
    is64 = sys.maxsize > 2**32
    log(f"Python: {sys.version.split()[0]} ({'64' if is64 else '32'}-bit)")

    device = frida.get_local_device()
    try:
        pid = device.spawn([FMW])
        log(f"Spawn PID: {pid}")
        session = device.attach(pid)
        script = session.create_script(JS)
        script.on("message", on_message)
        script.load()
        log("Script loaded")
        device.resume(pid)
        log("Resumed. Aguardando scans...")
    except Exception as e:
        log(f"[!] Erro: {type(e).__name__}: {e}")
        LOG_F.close()
        return 1

    log("")
    log("Ao ver [MOD crypt-like] e [TEA EXPORT], teremos o path/base correto.")
    log("Se aparecer o path do Moza (Program Files/MOZA), hookea ali.")
    log("Depois: no FirmwareManager clicar Update -> Instalar -> Cancelar")
    log("Ctrl+C para encerrar.")
    log("")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log("\n[detach]")
        try: session.detach()
        except: pass
    LOG_F.close()
    return 0

if __name__ == "__main__":
    sys.exit(main())
'@ | Set-Content -Path $scriptPath -Encoding UTF8

Write-Host "`n=== RODANDO V11 ===" -ForegroundColor Cyan
python $scriptPath

Remove-Item Env:QT_LOGGING_RULES -ErrorAction SilentlyContinue
Remove-Item Env:QT_FORCE_STDERR_LOGGING -ErrorAction SilentlyContinue
