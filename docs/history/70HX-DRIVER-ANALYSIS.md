# §4a: разбор драйвера 610.43.03 — почему WPR2 не защёлкивается

**Дата:** 2026-09-28
**Источник:** полные исходники `NVIDIA-kernel-module-source-610.43.03`,
найденные на машине в
`C:\Users\Administrator\Desktop\unlock - наработки\NVIDIA-kernel-module-source-610.43.03`
(версия совпадает с `gsp_ga10x.bin` из пакета — та же ветка 610).

**Итог одной строкой:** гипотеза «неверно заполнено `gfwImageSize`»
**опровергнута** — наш код делает ровно то же, что и драйвер. Формула
`WPR2` **подтверждена** и совпадает с нашей. Найдена **новая, не учтённая
нами величина** — `kgspGetWprEndMargin`, которую драйвер **вычитает** из
`gspFwWprEnd`, а наш `TARGET PROFILE` её игнорирует.

---

## 1. Ключевые файлы

| Файл | Что в нём |
|---|---|
| `src/nvidia/src/kernel/gpu/gsp/arch/turing/kernel_gsp_frts_tu102.c` | **главный**: команда FRTS, проверка результата, коды ошибок |
| `src/nvidia/src/kernel/gpu/gsp/arch/turing/kernel_gsp_tu102.c` | `kgspPopulateWprMeta_TU102` — раскладка FB, вызовы FWSEC |
| `src/nvidia/src/kernel/gpu/gsp/kernel_gsp.c` | `kgspGetWprEndMargin` (стр. 6552) |
| `src/nvidia/arch/nvalloc/common/inc/gsp/gsp_fw_wpr_meta.h` | структура `GspFwWprMeta` и карта раскладки FB |
| `src/nvidia/generated/g_kernel_gsp_nvoc.h` | HAL-диспетчеризация: для GA102/GA104 это **`_TU102`** |

Важно: `g_kernel_gsp_nvoc.h:1046` показывает, что для нашего чипа
диспетчеризация идёт в `kgspPopulateWprMeta_TU102`. То есть **разбор
`turing` — это разбор нашего GA104, а не соседней архитектуры.**

---

## 2. Гипотеза §4a ОПРОВЕРГНУТА: команда FRTS у нас собрана верно

Драйвер, `s_prepareForFwsec_TU102` (строки 311–332):

```c
readVbiosDesc.version       = 1;
readVbiosDesc.size          = sizeof(readVbiosDesc);   // = 24
readVbiosDesc.gfwImageOffset = 0;
readVbiosDesc.gfwImageSize   = 0;                      // <-- НОЛЬ, как у нас
readVbiosDesc.flags          = FWSECLIC_READ_VBIOS_STRUCT_FLAGS;  // = 2

frtsCmd.frtsRegionDesc.version        = 1;
frtsCmd.frtsRegionDesc.size           = sizeof(...);   // = 20
frtsCmd.frtsRegionDesc.frtsRegionOffset4K = frtsOffset >> 12;
frtsCmd.frtsRegionDesc.frtsRegionSize = 0x100;          // 1 МБ в 4К-блоках
frtsCmd.frtsRegionDesc.frtsRegionMediaType = 2;         // FB
```

Структуры (`kernel_gsp_frts_tu102.c:104–131`):

```c
typedef struct { NvU32 version, size; NvU64 gfwImageOffset;
                 NvU32 gfwImageSize, flags; } FWSECLIC_READ_VBIOS_DESC;   // 24 байта
typedef struct { NvU32 version, size, frtsRegionOffset4K,
                 frtsRegionSize, frtsRegionMediaType; } FWSECLIC_FRTS_REGION_DESC; // 20 байт
typedef struct { FWSECLIC_READ_VBIOS_DESC readVbiosDesc;
                 FWSECLIC_FRTS_REGION_DESC frtsRegionDesc; } FWSECLIC_FRTS_CMD;
```

**Сравнение с нашим кодом** (`fwsec_boot_gsp_sig`):

| Поле | Драйвер | Наш код | |
|---|---|---|---|
| `readVbiosDesc.version` | 1 | `c[0]=1` | ✅ |
| `readVbiosDesc.size` | 24 | `c[1]=24` | ✅ |
| `gfwImageOffset` | 0 | `c[2]=0, c[3]=0` | ✅ |
| `gfwImageSize` | **0** | `c[4]=0` | ✅ |
| `flags` | **2** | `c[5]=2` | ✅ |
| `frtsRegionDesc.version` | 1 | `c[6]=1` | ✅ |
| `frtsRegionDesc.size` | 20 | `c[7]=20` | ✅ |
| `frtsRegionOffset4K` | `frtsOffset>>12` | `c[8]=FWSEC_FRTS_OFFSET>>12` | ✅ |
| `frtsRegionSize` | `0x100` | `c[9]=0x100` | ✅ |
| `frtsRegionMediaType` | 2 | `c[10]=2` | ✅ |

**Вывод: `gfwImageSize = 0` — это не ошибка, а штатное значение драйвера.**
Моя гипотеза §4a была неверна. План «проставить настоящий `gfwImageSize` из
драйвера» не имеет смысла: настоящий `gfwImageSize` и есть ноль.

`FWSECLIC_READ_VBIOS_STRUCT_FLAGS (2)` — константа, не битовая маска
регистров, а **поле дескриптора**. Наше `c[5]=2` верно.

---

## 3. Структура `DMAP` подтверждена побайтово

Расшифрованная нами в [70HX-VBIOS-ANALYSIS.md §5](70HX-VBIOS-ANALYSIS.md)
структура `FALCON_APPLICATION_INTERFACE_DMEM_MAPPER_V3` (строки 80–99) имеет
**ровно** тот вид, что мы нашли в DMEM:

| Смещение | Поле драйвера | Значение из вашего ROM |
|---|---|---|
| `0x000` | `signature` | `0x50414D44` = `"DMAP"` ✅ |
| `0x004` | `{version:16, size:16}` | `0x00400003` → version 3, size 0x40 ✅ |
| `0x008` | `cmd_in_buffer_offset` | `0x000007C0` ✅ |
| `0x00C` | `cmd_in_buffer_size` | `0x00000040` (64) ✅ |
| `…` | `cmd_out_*`, `nvf_img_*`, … | — |
| `0x02C` | **`init_cmd`** | `0` в ROM; мы пишем `0x15` ✅ |

Смещение `init_cmd`: `0x008 + 9*4 = 0x2C` от начала `DMAP`, то есть
`0x560 + 0x2C = 0x58C` — **абсолютно** то, куда пишет наш код (`mapper[11]`
при `mapper = dmem + 0x560`).

`CMD_FRTS = 0x15`, `CMD_SB = 0x19` — совпадает с нашим `FWSEC_CMD_FRTS`.

**Значит и `cmdInBufferOffset`, и `initCmd` в коде верны** (это уже было
проверено по ROM, теперь подтверждено исходником).

---

## 4. Формула WPR2 ПОДТВЕРЖДЕНА — наша верна

Драйвер (`kgspExecuteFwsec_TU102`, строки 506–525):

```c
wpr2LoVal     = DRF_VAL(_PFB, _PRI_MMU_WPR2_ADDR_LO, _VAL, data);
expectedLoVal = frtsOffset >> NV_PFB_PRI_MMU_WPR2_ADDR_LO_ALIGNMENT;
if (wpr2LoVal != expectedLoVal) { /* FAIL */ }
```

Из `dev_fb.h`:

```c
#define NV_PFB_PRI_MMU_WPR2_ADDR_LO          0x001FA824   // наше — верно
#define NV_PFB_PRI_MMU_WPR2_ADDR_HI          0x001FA828   // наше — верно
#define NV_PFB_PRI_MMU_WPR2_ADDR_LO_VAL      31:4
#define NV_PFB_PRI_MMU_WPR2_ADDR_LO_ALIGNMENT 0x0000000C
```

Проверка арифметики (Python, точные числа):

```
70HX 8GB :  frts=0x1F7E00000      ← текущее значение (с TARGET_WPR_END_MARGIN)
   драйвер: (frts>>0xC)<<4 = 0x01F7E000
   наша:      frts>>8     = 0x01F7E000     MATCH
90HX 10GB:  frts=0x27FE00000
   драйвер: (frts>>0xC)<<4 = 0x27FE000
   наша:      frts>>8     = 0x27FE000     MATCH
```

> **Устаревшее число.** Старые редакции этого раздела подставляли сюда
> `frts=0x1FFE00000` — это значение **до** добавления маржи
> (`TARGET_WPR_END_MARGIN`). Формула кодирования WPR2 от маржи не зависит и
> вывод `MATCH` остаётся в силе, но проверяемое число должно быть текущим:
> `0x1F7E00000`. См. строки `GEOM  margin=0x8000000 (128 MB) wprEnd=0x1F7F00000
> frts=0x1F7E00000` в логах прогонов.

**`ALIGNMENT = 0xC`, а `VAL` лежит в битах `31:4`, поэтому `(frts>>12)<<4`
математически равно `frts>>8`.** Наша формула `TARGET_WPR2_LO = frtsOffset >> 8`
**правильная**, это не экстраполиция по одному замеру, а тождество.

Заодно: смещения регистров `0x1FA824`/`0x1FA828` в нашем коде совпадают
с заголовком драйвера, а `scratch0e` (`0x1438 = 0x1400 + 0x0E*4`) — с
`NV_PBUS_VBIOS_SCRATCH(0x0E)`. **Адреса в коде не перепутаны.**

### 4.1 WPR2_HI водитеру не нужен

Драйвер проверяет только `wpr2HiVal != 0` (строка 508) — «WPR2 найден». Точное
значение HI он не сверяет. Наша экстраполяция `hi = lo + 0xE00` из одного
замера на 10 ГБ для **проверки успеха несущественна** — она влияет только на
наше условие «принять как успех».

### 4.2 Постовое `0x1FFFFE00` — это НЕ FRTS-WPR2

```
наблюдаемое  WPR2_LO = 0x1FFFFE00
его VAL-поле (31:4)   = 0x1FFFFE0
обратно во frts       = 0x1FFFFE0000  (128 ГБ)
```

Никакая геометрия FB не даёт такого `frtsOffset`. Значит
`0x1FFFFE00/0x00000000` — это **не FRTS-WPR2**, а какое-то другое
состояние регистра после POST (вероятно, дефолтное/сбросное значение).
**Сравнивать с ним бессмысленно** — и это объясняет, почему оно не меняется:
FWSEC туда и не пишет, потому что FRTS не отрабатывает.

---

## 5. НАЙДЕНО: `kgspGetWprEndMargin` — величина, которую мы не вычитаем

`kernel_gsp_tu102.c:817`:

```c
pWprMeta->gspFwWprEnd = NV_ALIGN_DOWN64(
        vbiosReservedOffset - kgspGetWprEndMargin(pGpu, pKernelGsp),
        WPR_ALIGNMENT);
pWprMeta->frtsSize    = kgspGetFrtsSize(pGpu, pKernelGsp);
pWprMeta->frtsOffset  = pWprMeta->gspFwWprEnd - pWprMeta->frtsSize;
```

`kernel_gsp.c:6552` — из чего состоит маржа:

```c
wprEndMargin = (RM_GSP_WPR_END_MARGIN_MB из реестра) << 20;
if (wprEndMargin == 0) {                       // реестр не задан — наш случай
    wprEndMargin += kpmuReservedMemorySizeGet(...);
    wprEndMargin += kgspGetFrtsSize_HAL(...);          // 1 МБ
    wprEndMargin += pKernelGsp->gspRmBootUcodeSize;    // 0x6000
    wprEndMargin += pWprMeta->sizeOfRadix3Elf;         // ~84 МБ (.fwimage)
    wprEndMargin += kgspGetFwHeapSize(...);
    wprEndMargin += kgspGetNonWprHeapSize(...);
}
```

**Наш `TARGET PROFILE` маржу вычитает — это уже исправлено (2026-09-29).**

```
было:  WPR_END = (FB - PRAMIN) & ~0x1FFFF              ← маржа игнорировалась
стало: WPR_END = ((FB - PRAMIN) - margin) & ~0x1FFFF   ← как в драйвере
```

Константа `TARGET_WPR_END_MARGIN = 0x08000000` (128 МБ) определена в
`src/unlock_v2.c`, и результат виден в каждом прогоне:

```
GEOM  margin=0x8000000 (128 MB)  wprEnd=0x1F7F00000  frts=0x1F7E00000  expectWPR2=0x01F7E000/0x01F7EE00
```

Оценка ниже — обоснование выбора величины, оно остаётся в силе: реальные
числа из лога (`sizeOfRadix3Elf = 0x5053000`, `gspRmBootUcodeSize = 0x6000`,
`frtsSize = 0x100000`) плюс типичные heap-размеры давали **порядка
100–150 МБ**. Для 8 ГБ кадрового буфера это **~1,5–2 %** объёма, но
`frtsOffset` уезжал примерно на 128–160 МБ ниже прежнего значения.

> Открытым остаётся не «внедрить маржу», а **точное значение маржи,
> выведенное драйвером из кучи**: `kgspGetWprEndMargin` в `gspFwWprEnd`
> у нас отсутствует, мы подставляем константу. Экстраполяция сработала
> (WPR2 защёлкнулся, анлок подтверждён), но это подбор, а не тождество.

`FRTS` обязан располагаться в конце распребительной области, над
`bootBin` (boot bin) и ELF GSP — иначе при защёлкивании WPR2 под защиту
попадёт **чужой регион**, и FWSEC откажется его лочить. Это ровно тот
класс «молчаливого несовпадения условий», который мы наблюдаем.

Точное значение маржи вычисляется в двух кусках:

* `kpmuReservedMemorySizeGet` — свой HAL, найдём;
* `kgspGetFwHeapSize` / `kgspGetNonWprHeapSize` — зависят от
  `kmemsysGetUsableFbSize` и лимитов GSP, читаются из конфигурации;
* либо берётся **из уже заполненной meta** (строка 6573–6577):
  `wprEndMargin = gspFwWprEnd - nonWprHeapOffset` — это путь «повторная
  попытка».

Возможность задать маржа извне — реестр `RM_GSP_WPR_END_MARGIN`
(`MB` = биты `30:0`, `APPLY` = бит `31`) — подсказывает, что значение
подбирается экспериментально. Это делает **перебор маржи** самым
перспективным следующим экспериментом: он не требует ни новой прошивки,
ни новой подписи, только одной константы в `TARGET PROFILE`.

---

## 6. Плюс: найден код ошибки FWSEC, который мы не читаем

`kernel_gsp_frts_tu102.c:133–139`:

```c
#define NV_VBIOS_FWSECLIC_SCRATCH_INDEX_0E        0x0E
#define NV_VBIOS_FWSECLIC_FRTS_ERR_CODE           31:16
#define NV_VBIOS_FWSECLIC_FRTS_ERR_CODE_NONE      0x00000000
```

Драйвер **первым делом** после `kgspExecuteHsFalcon` читает
`NV_PBUS_VBIOS_SCRATCH(0x0E)` и требует `FRTS_ERR_CODE == 0`. Только потом
смотрит на WPR2.

Наш лог печатает `scratch0e=0x00000000` — то есть **старшие 16 бит нулевые,
FWSEC отчитывается об успехе**. Это важнейшая деталь: она согласуется с
нашим выводом «FWSEC отработал молча», но теперь это **подтверждено по
спецификации**, а не по догадке. Значит проверять «упал ли FWSEC» не нужно —
нужно понять, почему он, сообщив об успехе, не защёлкнул WPR2.

Также у драйвера есть проверка `wpr2HiVal == 0 → "no initialized WPR2
found"`. У нас HI = `0x00000000` — **ровно этот случай**. То есть если бы
FWSEC был запущен повторно, драйвер упал бы на этой же проверке.

---

## 7. Что делать дальше (пересмотренные приоритеты)

| # | Действие | Стоимость | Основание |
|---|---|---|---|
| ~~**1**~~ | ~~**Перебор `WPR_END_MARGIN`**~~ | — | **ВЫПОЛНЕНО 2026-09-29:** принято 128 МБ (`TARGET_WPR_END_MARGIN = 0x08000000`), WPR2 защёлкнулся, анлок подтверждён ×11.25. Перебор больше не нужен |
| **1′** | Уточнить маржу до точного значения, выводимого драйвером из кучи | чтение исходников | §5 — `kgspGetWprEndMargin` отсутствует, у нас константа; это подбор, а не тождество |
| 2 | Проверка `FWSECLIC` scratch `0x0E`/`0x15` с масками полей | правка логирования | §6 — даст код ошибки вместо «нулей» |
| 3 | Проверить `cmd_out_buffer` (0x40-байтовое окно) | дамп 256 Б | драйвер его не читает, но FWSEC может писать туда диагностику |
| 4 | Найти `kpmuReservedMemorySizeGet` и heap-размеры | чтение исходников | §5 — уточнит маржу вместо перебора |

### Как оформить перебор

`TARGET_WPR_END` сейчас:

```c
#define TARGET_WPR_END  (TARGET_VGA_WS_OFFSET & ~(0x1FFFFULL))
```

Нужно добавить маржу с переключателем, чтобы одну сборку можно было
проверить на нескольких значениях либо прогнать значения последовательно
за один заход. Ориентиры для перебора (в порядке возрастания):

```
0            (текущее поведение — заведомо неверно)
0x04000000   64 MB
0x06000000   96 MB
0x08000000   128 MB
0x0A000000   160 MB
0x10000000   256 MB
```

Критерий успеха — в логе `FWSEC OK` / `WPR2 УСТАНОВЛЕН`, либо появление
ненулевого `WPR2_HI` (сейчас он `0x00000000`).

**Риск для карты: нулевой.** Маржа влияет только на адрес, который мы
просим FWSEC защёлкнуть; максимум — FWSEC откажется. `WPR2` при неудаче
не защёлкивается, и следующий POST всё сбрасывает. Зато **ошибка в выборе
значения может защёлкнуть защиту на чужом регионе** — поэтому перебор
следует делать аккуратно, проверяя в логе, что FWSEC отчитался успехом
и `WPR2` оказался в ожидаемом месте, а не в каком угодно.

---

## 8. Сводка: что оказалось верным

| Проверка | Результат |
|---|---|
| Команда FRTS целиком | ✅ **побайтово совпадает** с драйвером |
| `gfwImageSize = 0` | ✅ так в драйвере (гипотеза §4a мертва) |
| `flags = 2` | ✅ так в драйвере |
| Структура `DMAP` | ✅ совпадает поле в поле |
| `initCmd` по `0x58C` | ✅ совпадает |
| `cmdInBufferOffset = 0x7C0` | ✅ совпадает |
| Смещения `WPR2` (`0x1FA824/28`) | ✅ совпадают с `dev_fb.h` |
| Формула `WPR2_LO = frts>>8` | ✅ **тождественно** формуле драйвера |
| `scratch0e = 0x1438` | ✅ совпадает |
| **`kgspGetWprEndMargin` в `gspFwWprEnd`** | ❌ **ОТСУТСТВУЕТ у нас** |
