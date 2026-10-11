# Разблокировка NVIDIA CMP 70HX

UEFI-загрузчик снимает вычислительные и часть графических ограничений
**NVIDIA CMP 70HX** (GA104, 8 ГБ, PCI ID `10de:248a`) до старта Windows.
После работы загрузчика Windows запускается без дополнительного POST, поэтому
состояние GPU сохраняется.

## Результат

| Область | Подтверждённое состояние |
|---|---|
| Compute | потолок issue-rate 1/32 снят, ×11,25 по `pp512` |
| Render | `GFX_SPEED_SELECT=0x4`, Cyberpunk 2077 50 fps / 135 Вт |
| Частота | 1545 МГц под нагрузкой, без троттлинга |
| Конфигурация | 30 SM / 3840 CUDA cores; native RM подтвердил все 15 активных TPC в GFX |
| PCIe | Gen1 x4; доступный путь к Gen2 исчерпан серией E-A…E-P |
| Время UEFI-прогона | около 4,9 с вместо 218,1 с |

Подробности и границы доказательств: [`docs/STATUS.md`](docs/STATUS.md).

## Как это работает

1. Приложение находит CMP 70HX и подготавливает защищённую область WPR2.
2. Через подписанный SEC2 booter и stack-canary exploit исполняется
   привилегированный V67 payload.
3. Открываются PLM, compute-селекторы SS0/SS1 и две render-маски.
4. FLR сбрасывает временное защищённое состояние, но нужные селекторы
   переживают переход к Windows.
5. Встроенный FAT32 reader загружает `bootmgfw.efi`; SimpleFileSystem намеренно
   не используется из-за зависаний на некоторых AMI-платах.

Анлок волатилен: после полного reboot/POST загрузку с флешки нужно повторить.

## Требования

| Компонент | Требование |
|---|---|
| GPU | CMP 70HX GA104, 8 ГБ, `10de:248a` |
| ОС | Windows на GPT/UEFI |
| Above 4G Decoding | Enabled |
| Resizable BAR | Auto/Enabled |
| Secure Boot | Disabled — EFI не подписан |
| CSM | Disabled |
| Fast Boot | Disabled |
| USB | от 512 МБ; для журнала — от 4 ГБ |

Для игр стоковый NVIDIA-драйвер недостаточен: он отдельно блокирует CMP в
render-пути. Используйте совместимую версию
[NVIDIA-patcher](https://github.com/dartraiden/NVIDIA-patcher).

## Установка стабильного релиза 1.0.0

1. Скачайте `cmp70hx-unlock-1.0.0.img.gz` и `SHA256SUMS` со страницы
   [Releases](https://github.com/nvlight/cmp70hx-unlock/releases).
2. Распакуйте `.gz` и запишите `.img` через Rufus в режиме DD либо Etcher.
3. Проверьте SHA-256 скачанного файла:

   ```powershell
   Get-FileHash .\cmp70hx-unlock-1.0.0.img.gz -Algorithm SHA256
   ```

4. В BIOS отключите Secure Boot, CSM и Fast Boot, включите Above 4G.
5. Перезагрузитесь, откройте boot-меню (обычно F12/F8/Del) и выберите USB.

Релизный загрузчик 1.0.0:

```text
MD5  C68878AFAFD0D2D246D2E25C5ACBD888
size 680960 bytes
```

Образ имеет MBR + FAT32 с типом раздела `0xEF` и содержит:

- `EFI\BOOT\BOOTX64.EFI` — загрузчик;
- `VERSION.txt` — версия, коммит и MD5;
- `README.txt` — краткая инструкция.

`gsp_ga10x.bin` не нужен: начиная с v3.42 загрузчик его не читает.

### Почему флешка не видна в Проводнике

Windows не назначает букву ESP-разделу `0xEF` автоматически. Это нормально и
не мешает загрузке или чтению raw-журнала. Для ручного просмотра:

```powershell
powershell -ExecutionPolicy Bypass -File out\assign-stick-letter.ps1
```

Если USB отсутствует в boot-меню, проверьте CSM/Fast Boot и полностью очистите
старую backup-GPT перед повторной записью образа. Подробнее:
[`docs/GOTCHAS.md`](docs/GOTCHAS.md).

## Кандидат 1.0.1

Ветка `main` готовится к 1.0.1. Кандидат использует проверенный аппаратный
release-бинарник:

```text
MD5  3C076AF7CF7C2BDA65FDA01F7678982C
size 680960 bytes
tag  rollback-2026-10-10
```

Он включает исправленный поиск PCI capability и обновлённую инфраструктуру.
Пострелизные эксперименты находятся за `RENDER_MATRIX=1` и не меняют обычную
сборку. **1.0.1 ещё не опубликован:** до тега требуется аппаратная проверка
готового образа по [`BUILDING.md`](BUILDING.md).

## Сборка из исходников

Нужны x86_64 Linux/WSL, GCC 12, gnu-efi, binutils, Python 3 и локально
полученные firmware/payload blobs. Блобы и ROM не распространяются проектом.

```bash
cd src
BLOBS=/path/to/blobs bash build.sh
```

Результат — один `src/unlock_v3r.efi`. GCC 15 создаёт другой бинарник и не
подходит для воспроизводимого релиза. Полная процедура:
[`BUILDING.md`](BUILDING.md).

Создание кандидата образа в Windows с правами администратора:

```powershell
powershell -ExecutionPolicy Bypass -File out\make-image.ps1 -Version 1.0.1
powershell -ExecutionPolicy Bypass -File out\verify-image.ps1
```

## Аппаратная приёмка

Перед загрузкой нового образа очистите старый raw-журнал — образ 256 МиБ не
перезаписывает область LBA 4 000 000:

```powershell
out\reset-stick-log.ps1
# Перезагрузка и выбор USB выполняются человеком.
out\pull-log.ps1 -Tag <метка>
out\verify-log.ps1 out\usb-log-<метка>.txt
out\verify-image.ps1 -CompareOnly
```

Успешный лог обязан содержать:

```text
G2RMC ... already open 0 of 2
G2RMC ... already open 1 of 2
G2GFX ... GFX_SPEED_SELECT=0x00000004 SET
G2SUM ... readback 0x00000004 OK
END   ss0=0x88888888 ss1=0x00000008 PLM=0xFFFFFFFF
END   ---- end of log ----
```

Промежуточные строки без последнего `END` не доказывают завершение.

## Документация

- [`docs/STATUS.md`](docs/STATUS.md) — текущее техническое состояние;
- [`KNOWN-ISSUES.md`](KNOWN-ISSUES.md) — действующие ограничения;
- [`BUILDING.md`](BUILDING.md) — сборка, образ и release checklist;
- [`docs/FLASH-AND-LOG.md`](docs/FLASH-AND-LOG.md) — работа с USB и журналом;
- [`docs/LOGGING.md`](docs/LOGGING.md) — формат raw-журнала;
- [`docs/REGISTERS.md`](docs/REGISTERS.md) — карта регистров;
- [`docs/GR-DRIVER-PATCH.md`](docs/GR-DRIVER-PATCH.md) — статический перенос и
  аппаратная A/B-матрица экспериментального GR-патча 616.92;
- [`out/BUILDS.md`](out/BUILDS.md) — актуальные MD5 и аппаратные эталоны;
- [`docs/history/`](docs/history/README.md) — полная хронология исследований.

## Лицензия и происхождение

Код распространяется по GPL-2.0-only; см. [`LICENSE`](LICENSE) и
[`NOTICE`](NOTICE). Репозиторий не распространяет подписанные NVIDIA firmware,
VBIOS ROM и exploit payload. Проект основан на исследованиях xrip,
WildFlash1st, bendy2, Jon Pry и cmpunlocker; подробные ссылки сохранены в
исторической документации и `NOTICE`.

## Отказ от ответственности

Код выполняет привилегированные записи в GPU до загрузки ОС. Используйте его
только на поддерживаемой карте, сохраняйте исходный VBIOS и не прерывайте
аппаратный прогон. Все действия выполняются на ваш риск.
