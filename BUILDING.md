# Сборка, запись и приёмка

Этот документ описывает единственный поддерживаемый release-путь CMP 70HX.
История экспериментов вынесена в [`docs/history/`](docs/history/README.md).

## 1. Среда

Поддерживаемая сборка выполняется на x86_64 Linux/WSL:

```bash
sudo apt install build-essential gcc-12 gnu-efi python3
```

Для воспроизводимого PE нужен **GCC 12**. GCC 15 создаёт файл другого размера.
`src/build.sh` может храниться с CRLF: `bash -n` это допускает, а реальный
запуск падает. Делайте временную LF-копию рядом с исходником, чтобы вычисление
`dirname "$0"` продолжало указывать на `src/`:

```bash
mkdir -p /tmp/cmp70hx-gcc12
printf '#!/bin/sh\nexec /usr/bin/gcc-12 "$@"\n' > /tmp/cmp70hx-gcc12/gcc
chmod +x /tmp/cmp70hx-gcc12/gcc
cd src
tr -d '\r' < build.sh > _build-lf.sh
chmod +x _build-lf.sh
PATH=/tmp/cmp70hx-gcc12:$PATH BLOBS=/path/to/blobs bash _build-lf.sh
rm -f _build-lf.sh
```

Проверенные комбинации включают gnu-efi 3.0.15/4.0.0 и современные binutils.
Явный input format и список PE-секций в `build.sh` менять нельзя.

## 2. Локальные блобы

Firmware, VBIOS и exploit payload не входят в репозиторий. Каталог `blobs/`,
`*.bin` и `*.rom` игнорируются намеренно. Для release-сборки нужны:

```text
v67_payload.bin
booter_ucode_dbg_patched.bin
booter_ucode_prod_patched.bin
gsp_rm_boot_dbg.bin
fwsec_ga104.bin
fwsec_ga104_sig.bin
fwsec_ga104_prod_sig0.bin
fwsec_ga104_prod_sig1.bin
fwsec_ga104_prod_sig2.bin
sec2_ucode_vbios_49_patched.bin
sec2_ucode_vbios_89_patched.bin
```

FWSEC и подписи должны происходить от GA104. Не подставляйте GA102/CMP 90HX.
Извлечение FWSEC из локального VBIOS выполняют скрипты `src/tools/`.

## 3. Release-сборка

```bash
cd src
BLOBS=/path/to/blobs bash build.sh
```

Обычная сборка создаёт ровно один файл: `src/unlock_v3r.efi`. Он одновременно
рабочий загрузчик и rollback-бинарник. Compute-only варианта нет.

Обязательные флаги release-цели задаются в `build.sh`:

```text
RELEASE_BUILD MULTI_CARD PCIE_GEN2_REJOIN FULL_NOGEN2
GEN2_LINK_TRY RENDER_MASKS CHIP_SIZE_SCAN=1
```

`RENDER_MATRIX=1` строит экспериментальные варианты и не используется для
релиза. В частности, отсутствие `RENDER_MASKS` оставляет рабочий compute, но
ломает графику — поэтому такой дефект легко пропустить.

Read-only ReBAR/XVE census собирается только явно:

```bash
REBAR_PROBE=1 BLOBS=/path/to/blobs bash build.sh
```

Скрипт сначала воспроизводит обычный `unlock_v3r.efi`, затем создаёт отдельный
`unlock_rebar_probe.efi`. Обычная release-цель не получает код или строки
`RBPROBE`. Для записи используйте `out\flash-build.ps1 -RebarProbe`, а не
`-AllowNewBuild`. `REBAR_EXPERIMENT=1` намеренно заблокирован до полного
аппаратного RBPROBE-журнала и отдельного review write/rollback-пути.

### PE-секции

Финальный `objcopy` обязан явно сохранять:

```text
.text .sdata .data .rodata .dynamic .dynsym .reloc .rela
```

`.rodata` содержит UTF-16 строки диагностики. Шаблон `.rel*` захватывает
`.rela.plt` и создаёт некорректную PE-секцию. Используйте `-I elf64-x86-64` и
`-O pei-x86-64` ровно как в скрипте.

## 4. Идентификация результата

Текущий проверенный аппаратный эталон:

```text
tag   rollback-2026-10-10
MD5   3C076AF7CF7C2BDA65FDA01F7678982C
size  680960 bytes
```

Он является базой кандидата 1.0.1. История других checkout находится в
[`out/BUILDS.md`](out/BUILDS.md). Никогда не сравнивайте бинарник с MD5 другого
коммита или compiler toolchain.

Проверьте профиль и ключевые маркеры как UTF-16LE:

```powershell
$p = 'src\unlock_v3r.efi'
$d = [IO.File]::ReadAllBytes($p)
$md5 = (Get-FileHash $p -Algorithm MD5).Hash
"$md5 $($d.Length)"
foreach ($s in 'CMP 70HX (GA104)','FBP    SKIPPED','CMPUNLOG v1 ',
                 'GFX_SPEED_SELECT','G2RMS','G2RCC') {
    $needle = [Text.Encoding]::Unicode.GetBytes($s)
    $found = $false
    for ($i=0; $i -le $d.Length-$needle.Length; $i++) {
        $ok = $true
        for ($j=0; $j -lt $needle.Length; $j++) {
            if ($d[$i+$j] -ne $needle[$j]) { $ok=$false; break }
        }
        if ($ok) { $found=$true; break }
    }
    "{0}: {1}" -f $s, $(if ($found) {'PRESENT'} else {'MISSING'})
}
```

Профиль `CMP 90HX (GA102)` должен отсутствовать.

## 5. Запись development-бинарника

Если задача явно включает подключённую тестовую флешку, весь безопасный цикл
copy → hash → markers → write → verify выполняет:

```powershell
powershell -ExecutionPolicy Bypass -File out\flash-build.ps1
```

Скрипт сам находит носитель либо принимает `-Stick X:` и отказывается писать,
если эталон/маркеры не совпали. `-AllowNewBuild` используется только для
намеренно нового экспериментального бинарника; это не способ обойти проверку.

Старый `BOOTX64.EFI` удаляется перед копированием: замена поверх существующего
файла опасна при внезапном reboot. Агент не перезагружает машину, не нажимает
F12 и не прерывает текущий прогон — это делает пользователь.

## 6. Журнал после загрузки

Перед загрузкой нового образа очистите старый raw-журнал:

```powershell
out\reset-stick-log.ps1
```

После возврата в Windows:

```powershell
out\pull-log.ps1 -Tag <метка>
out\verify-log.ps1 out\usb-log-<метка>.txt
```

Не используйте `-NoSave` для доказательного прогона. `pull-log.ps1` сохраняет
транскрипт с повторной сводкой; счётные проверки должны работать только с телом
между баннерами, как делает `verify-log.ps1`.

Порядок приёмки:

1. есть `END   ---- end of log ----`;
2. профиль равен CMP 70HX и геометрия совпадает;
3. render-маски открыты 2 из 2;
4. `GFX_SPEED_SELECT=0x4` подтверждён readback;
5. SS0/SS1/PLM имеют ожидаемые значения;
6. `verify-log.ps1` завершился кодом 0.

Статусы «собрано», «записано», «загружено» и «лог PASS» различаются. Без
свежего завершённого лога изменение не проверено на железе.

## 7. Образ 1.0.1

На Windows с правами администратора:

```powershell
powershell -ExecutionPolicy Bypass -File out\make-image.ps1 -Version 1.0.1
powershell -ExecutionPolicy Bypass -File out\verify-image.ps1
```

Результат в `dist/`:

```text
cmp70hx-unlock-1.0.1.img
cmp70hx-unlock-1.0.1.img.gz
SHA256SUMS
```

`verify-image.ps1` разбирает MBR/FAT32 без монтирования, сверяет загрузчик,
`VERSION.txt`, геометрию и отсутствие ненужного `gsp_ga10x.bin`. Код возврата
должен быть 0.

Хэш целого образа не воспроизводим: FAT32 serial и timestamps меняются. MD5
загрузчика внутри образа обязан совпадать с собранным `unlock_v3r.efi`.

## 8. Release checklist 1.0.1

1. Чистая release-сборка GCC 12 совпала с `3C076AF7…`, 680960 байт.
2. Образ создан с `-Version 1.0.1`; статическая проверка вернула 0.
3. Образ записан на реальный USB после очистки старой разметки при необходимости.
4. Старая область лога очищена до загрузки.
5. Целевая машина увидела USB в UEFI boot-меню.
6. CMP 70HX загрузилась, новый сохранённый лог завершён и прошёл проверку.
7. `verify-image.ps1 -CompareOnly` подтвердил фактически загруженный носитель.
8. В `out/BUILDS.md` записаны коммит, MD5, размер, лог и время.
9. Только после этого создаётся тег `v1.0.1` и публикуются `.img.gz` с
   соответствующим `SHA256SUMS`.

## 9. Что не входит в автоматизацию

- перезагрузка, F12 и физический выбор носителя;
- публикация GitHub Release;
- добавление закрытых firmware/payload blobs;
- признание экспериментального MD5 эталоном без аппаратного PASS.

Практические детали USB: [`docs/FLASH-AND-LOG.md`](docs/FLASH-AND-LOG.md).
Формат журнала: [`docs/LOGGING.md`](docs/LOGGING.md).
