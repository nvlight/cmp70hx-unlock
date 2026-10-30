# Исследование игровой производительности CMP 70HX — 2026-10-30

## Область и базовая точка

Период поиска: **2026-10-15 00:00 UTC — 2026-10-30 23:59 UTC**. Цель остаётся
строго CMP 70HX, GA104, 8 ГБ, `10de:248a`, Windows 10 и драйвер 616.92. Новый
драйвер 621.01 рассмотрен только статически. VBIOS не прошивается.

База R0 уже измерена в одинаковом встроенном тесте Cyberpunk 2077:
1920×1080, High, RT/DLSS/frame generation/vsync выключены, три прогона,
медиана **52,056 fps**. Аппаратный UEFI-журнал прошёл проверку. Полная
матрица R0–R3 и хэши артефактов находятся в `GR-DRIVER-PATCH.md`; R1–R3 не
дали игрового эффекта и не повторяются.

Статус в этом документе означает:

- **candidate** — есть конкретный следующий измеримый тест;
- **rejected** — направление уже опровергнуто применимым статическим или
  аппаратным доказательством;
- **not applicable** — код относится к другой архитектуре, ОС, версии драйвера
  или задаче и не переносится заменой PCI ID.

## Проверенные upstream-источники

| Источник и точная ревизия | Дата | Проверенные файлы/изменения | Факт и применимость к GA104/Windows 616.92 | Аппаратное доказательство | Итог |
|---|---|---|---|---|---|
| [Cyridd/cmpunlocker `05fef9d5`](https://github.com/Cyridd/cmpunlocker/commit/05fef9d5a24df66799e763fe3b568f0729fd5b67) | 2026-10-29 | `0004-cmp40hx-profiling-unlock.patch`, `CMP40_PROFILING.md` | Патч меняет только ответ `NV2080_CTRL_GPU_INFO_INDEX_CMP_SKU` для CMP 40HX `1f0b`. Не меняет GR, clocks, power, ReBAR или PCI ID. Это Linux 615.78.08, не Windows 616.92/GA104. | На 40HX подтверждён переход CUPTI support gate; сбор счётчиков не подтверждён. FPS не измерялся. | **not applicable** как performance-патч; идея годится только для будущей диагностики profiling gate. |
| [Cyridd/cmpunlocker `ddd67a1a`](https://github.com/Cyridd/cmpunlocker/commit/ddd67a1a9af91b4b4d9584107c838dda5d6ffa99) | 2026-10-29 | `cmp_glcore_patch/patch_glcore.cpp`, `CMP40_GSP_PIPELINE_THROTTLE_FINDINGS.md` | Для Linux `libnvidia-glcore.so` 580.173.02/610.57.04/615.78.08 подтверждены два emitter-вызова MME с аргументом 240. Локальный аудит Windows 616.92 уже не нашёл соответствующего вызова ни в `nvlddmkm.sys`, ни в user-mode библиотеках. | На 40HX Linux микробенч pipeline bind ускорен; это не игровой A/B. Для текущего стенда отрицательное статическое доказательство сохранено в `out/mme/`. | **rejected** для Windows 616.92. |
| [Cyridd/cmpunlocker `2e95a822`](https://github.com/Cyridd/cmpunlocker/commit/2e95a822363f0b51650901de6ea009eee19a7506) и [`2fd0049b`](https://github.com/Cyridd/cmpunlocker/commit/2fd0049b6bf95c9c94955c3aa1ab2f6c8287d0f4) | 2026-10-29 | Linux patch sets 580/615; `CMP170HX_PATCH_PORTABILITY.md` | ReBAR/Gen2/secure-booter реализации привязаны к TU106 и GA100. Общие имена HAL-файлов не доказывают совместимость регистров с GA104. | У Cyridd есть hardware result на 40HX, не на 70HX. | **not applicable** напрямую; ReBAR используется только как источник структуры probe/rollback. |
| [amoghmunikote/cmpunlocker `2c7e2ecd`](https://github.com/amoghmunikote/cmpunlocker/commit/2c7e2ecd7944e791fec040d2680036beb4a9327b) | 2026-10-27 | `driver/VERSION`; также просмотрены `db9e585f`, `0dbc0e3b`, `00fdf5c8`, `db440e42`, `7270661a`, `b1e1a14d` | В окне исследования добавлены 615.71.10 и GA100 vGPU/инструментальные изменения. Это CMP 170HX/GA100 Linux, не GA104 Windows. Исторические `300127f4` (2026-09-07) и `ee41902f` (2026-09-12) подтверждают назначение `cmp-sku-mask`: profiling. | Нет аппаратного A/B на CMP 70HX. | **not applicable**. |
| [Icyoung/cmpunlocker `bb2ae3fe`](https://github.com/Icyoung/cmpunlocker/commit/bb2ae3fe2d8f5e7d6574e2a15311f2589dda33bc) | 2026-09-29; новых commit в окне нет | `tools/gr_unlock/patch_gr_unlock.py` и GA100 GPC reconfiguration | Статический перенос GR-патча в 616.92 уже проверен fail-closed и затем испытан как R1–R3. | R3 Full: 52,057499 fps против R0 52,056000 (+0,003%), то есть шум. | **rejected**; не повторять R1–R3. |
| [dartraiden/NVIDIA-patcher `79b2364a`](https://github.com/dartraiden/NVIDIA-patcher/commit/79b2364a3dabe78a2678de41fb3eaac55917fbaf) | 2026-10-23 | `docs/README-WINDOWS.md`; Linux bump `670076e5` | Таблица совместимости переведена на Windows 621.01. Коммит меняет документацию/версию, а не добавляет доказанный GA104 performance-патч. Рабочий стенд остаётся на 616.92. | На этом проекте 621.01 аппаратно не запускался. | **candidate** только для отдельного будущего driver A/B, не для текущей серии. |
| [NVIDIA open modules tag `615.78.08`](https://github.com/NVIDIA/open-gpu-kernel-modules/releases/tag/615.78.08), peeled commit `1a82fbfd` | октябрь 2026 | официальный исходный Linux release | Это нормативный источник для проверки HAL/PCI структуры, но не бинарно совместимый источник для Windows 616.92. [Windows 621.01](https://www.nvidia.com/en-us/drivers/details/282469/) выпущен 2026-10-21. | Нет CMP 70HX Windows A/B. | **not applicable** как готовый патч; **candidate** как статический reference. |
| [xrip/cmp50hx-unlock `df2fe11b`](https://github.com/xrip/cmp50hx-unlock/commit/df2fe11b370bb52cc314576d0f2f5ae47ce908f8) | 2026-10-10; новых commit в окне нет | `03-cmp50-rebar.patch`, ReBAR docs; [discussion #64](https://github.com/xrip/cmp50hx-unlock/discussions/64) | ReBAR реализация — TU102/CMP 50HX и не переносится адресами вслепую. В discussion владелец 70HX сообщает физический x16-мод переносом отсутствующих конденсаторов, но не публикует PCB revision, BOM или карту позиций. | Публичное сообщение подтверждает один x16-мод, не универсальную процедуру пайки. | ReBAR **candidate** только через read-only GA104 probe; x16 **candidate** после идентификации PCB и измерения компонентов. |
| [pearlfortune/cmpunlocker `b5a0f718`](https://github.com/pearlfortune/cmpunlocker/commit/b5a0f718b4e37ecfbe2e7aff2ecd60e2465d30cb) | 2026-08-06; новых commit в окне нет | история и issues CMP unlock | Нового кода/доказательства для GA104 Windows 616.92 за период нет. | Нет нового A/B на нужном стенде. | **not applicable**. |
| [ForgeMiner `dc9c1a8e`](https://github.com/0xHashRaptor/ForgeMiner/commit/dc9c1a8e83e79f371967b1d2c5d5000589f26fc2), [`e537d764`](https://github.com/0xHashRaptor/ForgeMiner/commit/e537d764afecb6159fcf9ebc76554e1de28cca34) | 2026-10-22/28 | release docs 1.8.9/1.9.0 | 1.8.9 заявляет +11% NOID на CMP 70HX; это новый algorithm kernel закрытого miner-бинарника, не изменение GR/PCIe/частот и не игровой тест. 1.9.0 не добавляет новый 70HX unlock. | Только miner release result; нет Cyberpunk/PresentMon A/B и проверяемого patch source. | **not applicable** к игровому FPS. |
| [InterMiner `4cfb166b`](https://github.com/BaikalMine/InterMiner/commit/4cfb166b43aea05322ef095b6a126c428e5ac18b) | 2026-09-29; новых commit в окне нет | release docs 1.2.8-8 | Нового GA104/Windows performance-механизма за период нет. Miner throughput нельзя переносить на игровой render path. | Нет игрового A/B. | **not applicable**. |

## Вывод и порядок экспериментов

Нового подтверждённого software-патча, который должен поднять игровой FPS на
Windows 616.92, не найдено. Приоритеты:

1. новый R0 с телеметрией и resolution sweep;
2. read-only `REBAR_PROBE=1`;
3. физический x8→x16 A/B после идентификации PCB;
4. обратимый разгон без VBIOS flash и повышения напряжения;
5. ReBAR write-эксперимент только после положительного probe и отдельного
   review сохранения/rollback всех регистров.

`sku_unlock`/CMP SKU mask не переносится в `nvlddmkm.sys`: доказанный эффект
ограничен CUPTI profiling query. Старые R1–R3, `GFX_SPEED_SELECT`, Gen2 E-A…E-P
и MME 616.92 не переоткрываются без нового механизма.

## R0 и игровая матрица

Перед любым структурным изменением нужны свежий PASS UEFI-журнал и три R0:

| Шаг | Постоянные условия | Сохраняемые данные | Решение |
|---|---|---|---|
| R0 1920×1080 High | RT/DLSS/FG/vsync off; Windows 10; 616.92 | `summary.json`, PresentMon frames, SM/memory clocks, power, utilization, temperature, throttle reasons, PCIe width/speed, BAR1, H2D/D2H bandwidth | база медианы и 1% low |
| Resolution sweep | 1280×720, 1920×1080, 2560×1440; тот же High | те же данные, по три прогона | сильный рост FPS при снижении разрешения указывает на shader/ROP limit; слабый — на CPU/driver/PCIe |
| x8 stage | только подтверждённые номинал/корпус/назначение компонентов | cold boot, AER, width, bandwidth, VRAM soak, три игры | продолжать к x16 только без ошибок |
| x16 stage | та же software-конфигурация | те же данные | отделить эффект ширины от clocks/ReBAR |
| OC memory, затем core | малые ступени, без voltage/VBIOS | VRAM test, shader workload, три игры на ступень | остановка при artifact/error/Code 43/throttle |
| ReBAR A/B | только стабильный x16 и одинаковые clocks | BAR1, bandwidth, три игры, 1% low | последний эксперимент, не смешивать с x16 |

Игровой успех: медианный FPS ≥5% при разнице SM clock ≤2%, либо 1% low ≥10%
без регрессии среднего FPS, либо устранение воспроизводимого streaming stutter.
Изменение ширины PCIe/BAR1/power без игрового эффекта — технический PASS, но
не повышение игровой производительности.

## Граница физического x16-мода

До пайки нужны фотографии обеих сторон, точная маркировка PCB/revision,
прозвон линий 4–15 и сравнение пустых позиций с рабочими линиями 0–3. BOM
CMP 170HX/50HX не переносится. Если номинал, корпус или назначение соседних
AC-coupling конденсаторов не подтверждены измерением/схемой, ветка
останавливается без пайки. Сначала комплектуется только x8, затем после cold
boot/AER/bandwidth/VRAM soak — x16.

## Условие открытия ReBAR write-ветки

`REBAR_EXPERIMENT=1` сейчас намеренно заблокирован на этапе сборки. Его можно
реализовать только после сохранённого полного блока `RBPROBE BEGIN…END`, где
присутствуют BAR1 ReBAR capability с 8-ГиБ размером, корректное 64-битное окно
upstream bridge и пригодный EFI MMIO descriptor. Даже `VERDICT CANDIDATE` —
это лишь разрешение на review дизайна эксперимента, не доказательство
безопасности записи.

Будущая write-ветка обязана сохранять Command/BAR1/BAR3, все затрагиваемые XVE
и bridge registers, отключать decode перед sizing/reassignment, проверять
размер и начало/середину aperture, а при любом несовпадении откатывать значения
в обратном порядке. Она остаётся отдельной экспериментальной целью и никогда
автоматически не становится release.
