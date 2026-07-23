# Engenharia Reversa — Moza FSR1 (D03)

**Encerrado em:** 2026-07-23
**Objetivo original:** descobrir se dava pra customizar/substituir as 19 UIs do
display do volante Moza FSR1 (primeira geração).

---

## TL;DR — Conclusão

**Substituir/customizar UIs no FSR1 não é viável por software.**

A cifra TEA usada no firmware existe, foi identificada, mas a chave está no
bootloader do STM32 dentro do próprio volante. Sem sonda física SWD/JTAG
no chip, não há como extraí-la.

**O que dá pra fazer hoje** (via AZOM + SimHub):
- Trocar entre as 19 UIs pré-existentes via botão do volante ou SimHub
- Alimentar os campos das UIs com telemetria ao vivo do jogo (RPM, combustível, marcha, temps, tempo de volta)
- Ajustar rotação, brilho e unidades sem abrir Pit House

**O que continua impossível no FSR1 por software:**
- Criar layout novo do zero
- Modificar posição/estilo dos elementos gráficos existentes

---

## Descobertas técnicas

### Hardware

- MCU: **STM32** (Cortex-M, endereço flash em `0x08020000`)
- Codename interno do FSR1: **D03**
- Codename interno do FSR2: **W13**
- Fabricante: **Gudsen Technology**

### Formato do container de firmware

Válido para FSR1 (4419.bin, 1.4MB) e FSR2 (4516.bin, 115KB) — mesmo formato:

```
0x00-0x0F: Magic bytes  00 11 22 33 01 02 00 00 01 02 XX 04 00 00 00 00
0x38-0x5F: Product code em ASCII (ex: [RS21-D03-HW_FW-CU-V03][FSR][1][5])
0x78-0x7B: maxSectionSize = 8192 (0x2000)
0x7C-0x7F: num_sections
0x80-0x83: first flash address (0x08020000)
0x88-0x14F: hashes SHA-256/MD5 das seções
0x20A0-...: array de slots

Cada slot (8224 bytes = 32 header + 8192 data):
  +0:  flash address (uint32)
  +4:  orig size (uint32)
  +8:  comp size (uint32)
  +12: CRC32 (uint32)
  +16: MD5 (16 bytes)
  +32: dados (LZO comprimido + TEA cifrado)
```

FSR1 tem **175 slots**: 49 de código MCU + 126 de assets (bitmaps das 19 UIs).

### Cifra

- Algoritmo: **XTEA-like com 16 rounds**
- Delta constante: `0x9E3779B9` (padrão XTEA)
- Sum inicial: `0xE3779B90` (= delta × 16)
- Key size: 128 bits (16 bytes)
- Implementação: **`crypt.dll`** da Moza (11-28KB dependendo da versão)
- Exports: `Tea_Init`, `Tea_Encrypt`, `Tea_Decrypt`, `mbedtls_base64_*`

### Pipeline de cifra

```
Dado original → miniLZO compress → TEA encrypt → arquivo .bin no disco
```

Para decodificar seria: `disco → TEA_decrypt → LZO_decompress → original`.

### Estrutura arquitetural (a barreira)

```
DEV DA MOZA (empresa)     →  FirmwareManager cifra .bin com Tea_Encrypt
                                   ↓
Usuário baixa .bin cifrado →  Pit House ENVIA bin cifrado direto pro volante
                                   ↓
VOLANTE (STM32)            →  Descriptografa internamente (chave no bootloader)
```

**Consequências verificadas experimentalmente:**
- `Pit House` em uso normal **NÃO chama** Tea_Init/Tea_Encrypt/Tea_Decrypt
- Confirmado via **Frida hook** aplicado corretamente na `crypt.dll` da Moza
- Nenhum arquivo `.bin` de firmware é aberto durante navegação normal
- A cifra roda **apenas dentro do próprio volante**, não no PC

### Comando serial usado para trocar UI (funciona hoje)

```
7E 05 32 17 81 00 00 00 [INDEX] [checksum]
```

- Table 7, Param 6 (DashUiIndex)
- INDEX: 0-18 (existem 19 UIs, a 18 é escondida do Pit House)
- Checksum: `(soma_dos_bytes + 0x0D) mod 256`

Isso é o que Pit House, SimHub, AZOM e nosso script `enviar-dashuiindex.ps1` usam.
**Não envolve cifra** — é só um byte de índice.

---

## Jornada de investigação (resumo)

11 versões de scripts foram criados nessa investigação:

| Versão | O que fez | Resultado |
|--------|-----------|-----------|
| Localização dos firmwares | Achou `4419.bin` (FSR1) e `4516.bin` (FSR2) | ✓ |
| Parser do container | Decodificou estrutura de 175 slots × 8224 bytes | ✓ |
| Análise de entropia | Descobriu que dados estão cifrados (entropia ~8.0) | ✓ |
| Análise do Pit House | Localizou `crypt.dll` (11KB) — biblioteca isolada | ✓ |
| Análise da `crypt.dll` | Identificou XTEA r=16, string "Gudsen.88888888" | ✓ |
| Reimplementação Tea_Init em Python | Baseada em disassembly com SIMD — não bateu | ✗ |
| V4-V6 (análise estática das call sites) | Só `FirmwareManager.exe` importa crypt.dll | ✓ |
| V7-V10 (Frida hook em runtime) | Hook validado, mas Tea_* nunca chamada | Prova arquitetural |
| V11 (múltiplas crypt.dll) | Confirmou hook na DLL certa da Moza | Fecha a caixa |

---

## Arquivos úteis que ficam no projeto

Em `97-workspace/volante-moza-fsr/` (RE original):
- `enviar-dashuiindex.ps1` — troca UI via COM (uso diário)
- `analisar-pcapng-moza.ps1` — extrai pacotes Moza de captura Wireshark
- `validar-checksum-moza.ps1` — valida checksum de pacotes capturados
- `README.md` — documentação da RE original

Em `96-pessoal/reverse-engineering-moza/` (esta RE):
- `Engenharia reversa moza pithouse.txt` — script Frida atual (última tentativa)
- `RESULTADO_FINAL.md` — este documento

---

## O que ainda faz sentido investir (opcionais)

### 1. Deep dive na V4 do firmware do volante

O log da V6 mostrou que o volante do usuário atualizou para `FW-CU-V04` (nossa
análise foi do V03). Se a Moza adicionou features novas no V04 (tipo aceitar
`.mzdash` custom), isso mudaria o cenário. Vale baixar/analisar o firmware V04
se estiver disponível na pasta `fmw_bin/` do Pit House atual.

### 2. Hardware hacking (SWD)

Se você quiser MESMO customizar as UIs:
- Sonda **ST-Link V2** clone (~R$ 50-80 no ML)
- Abrir o volante e localizar os 4 pinos SWD (SWDIO, SWCLK, GND, 3.3V) no PCB
- Conectar e usar `pyocd` ou `st-flash` pra dumpar a flash do STM32
- Se **RDP (Read Protection)** não estiver ativado no chip, você dumpa o firmware
  interno (que tem o bootloader + Tea_Decrypt + chave hardcoded)
- Risco: **brick permanente se algo der errado**. Só faça com backup e sem pressa.

### 3. Engajar com o dev do AZOM

O giantorth tem RE bastante profundo do protocolo Moza. Vale abrir issue no
[repo do AZOM](https://github.com/giantorth/AZOM) perguntando se ele já explorou
customização de UI no FSR1. Se alguém vai resolver isso via software, provavelmente é ele.

---

## Referências

- [AZOM (giantorth) — SimHub plugin oficial não-oficial da Moza](https://github.com/giantorth/AZOM)
- [Boxflat (Lawstorant) — RE do protocolo Moza para Linux](https://github.com/Lawstorant/boxflat)
- [Boxflat — moza-protocol.md](https://github.com/Lawstorant/boxflat/blob/main/moza-protocol.md)
- [STM32 SWD Firmware Extraction Guide](https://industrialmonitordirect.com/blogs/knowledgebase/stm32-swd-firmware-extraction-via-openocd-tutorial)

---

*Investigação encerrada em 2026-07-23 após confirmação arquitetural de que a
cifra roda apenas dentro do volante e não no software do PC. Sem acesso físico
ao chip, não há como quebrar por vias de software.*
