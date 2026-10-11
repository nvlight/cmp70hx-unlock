# Native Linux RM topology census

Цель следующего опыта — узнать, какую часть уже активной аппаратной топологии
сам NVIDIA RM относит к graphics. Инструмент `src/tools/nv-rm-topology.py`
использует только публичные RM-команды `GET`; SET-команд и MMIO-записей в нём
нет. Он создаёт обычный RM-клиент и handles device/subdevice, но, в отличие от
полного `NVDevice` tinygrad, не создаёт graphics channel и не включает
`PERF_BOOST`.

## Среда

Нужна именно native Linux, не WSL, с загруженными совместимыми NVIDIA-модулями
и узлами `/dev/nvidiactl`, `/dev/nvidia-uvm`. Машина должна перед этим пройти
обычный UEFI-анлок с USB. Скрипт fail-closed проверяет PCI ID `10de:248a`.

Release EFI после успешного FLR не вызывает `bootmgfw.efi`, а возвращает
управление firmware BDS без POST; на текущем стенде следующим пунктом
BootOrder является Windows. Для этого опыта сначала сделайте Linux первым
обычным пунктом BootOrder, а USB выбирайте вручную через F12. Тогда после
анлока BDS должен продолжить именно в Linux без нового POST. Если плата всё же
делает второй POST или снова запускает USB, результат непригоден: порядок надо
вернуть и не считать такой Linux-сеанс разблокированным. Не выбирайте Linux
через отдельную перезагрузку после уже загруженной Windows — POST сотрёт
волатильный анлок.

Для Ubuntu 24.04 сначала установите базовые инструменты и заголовки текущего
ядра:

```bash
sudo apt update
sudo apt install git python3 pciutils linux-headers-$(uname -r) ubuntu-drivers-common
ubuntu-drivers devices
```

Для зафиксированных tinygrad-структур предпочтительна доступная в Ubuntu
ветка 580. Сначала проверьте имя пакета через `apt-cache policy
nvidia-driver-580-open nvidia-driver-580-server-open nvidia-driver-580`, затем
установите вариант с ненулевым `Candidate` (для GA104 предпочтителен `-open`).
После установки перезагрузитесь и проверьте `nvidia-smi`; CUDA Toolkit для
этого опыта не нужен.

Проверенная схема структур зафиксирована на tinygrad commit:

```text
2ff83c7f9081aef1f6e557d4b842f465885fdd5f
```

Подготовка сети возможна заранее на любой машине:

```bash
git clone https://github.com/tinygrad/tinygrad.git
git -C tinygrad checkout 2ff83c7f9081aef1f6e557d4b842f465885fdd5f
```

После загрузки целевой CMP 70HX:

```bash
set -o pipefail
python3 src/tools/nv-rm-topology.py --tinygrad /path/to/tinygrad \
  | tee rm-topology-cmp70hx.json
```

Обычные NVIDIA device nodes обычно доступны без root. Если получен именно
`Permission denied`, сначала проверьте права `/dev/nvidiactl` и
`/dev/nvidia-uvm`; не переходите к `sudo`, пока не сохранён точный текст
ошибки.

Если CMP не является первым NVIDIA GPU, укажите `--index N`. Другой commit
tinygrad отклоняется; `--allow-unpinned` предназначен только для осознанной
проверки совместимости структур. Код возврата `0` означает, что полный набор
обязательных topology-запросов ответил; `2` означает отсутствие хотя бы одного
обязательного ответа. Необязательные `GET_PHYS_GPC_MASK`, TPC reconfiguration,
ROP/ZCULL сохраняют ошибки в JSON, но сами по себе не делают core census
неполным.

## Что спрашивается

- effective и physical GPC masks;
- `physGfxGpcMask` и `numGfxTpc`;
- TPC и TPC-reconfiguration mask для GPC0..5;
- global SM order и число SM/TPC по мнению RM;
- ROP info, ZCULL info и ZCULL mask для GPC0..5.

Главный критерий: если `numGfxTpc=15`, все доступные по аппаратному снимку TPC
уже входят в graphics, и текущий render полностью открыт в пределах OTP
floorsweep. Если значение меньше 15, остаётся отдельная драйверная/GSP-маска,
локализацию которой можно продолжить. Этот запрос ничего не доказывает об
исправности отключённых GPC0/GPC1 и TPC GPC2.0.

JSON надо сохранить как доказательство вместе с версией драйвера и выводом
`nvidia-smi`; без фактического native Linux прогона ветка RM остаётся
непроверенной.

## Результат 2026-10-11

Native Ubuntu 24.04, kernel `7.0.0-30-generic`, NVIDIA `580.178.04`, pinned
tinygrad `2ff83c7f...`. Сопутствующий release-прогон на USB завершился за
4 918 мс и прошёл `verify-log.ps1` с compute+render и финальным `END`.

RM сообщил:

```text
gpcMask        = 0x0000003C
physGfxGpcMask = 0x0000003C
numGfxTpc      = 15
TPC masks      = 0, 0, E, F, F, F
global order   = 15 TPC / 30 SM
ROP            = 8 units / 64 operations
```

Это точно совпадает с UEFI census: все 15 физически активных TPC включены в
graphics. Дополнительной RM/GSP GFX-маски нет; доступный 30-SM render открыт
полностью. Получение 48 SM потребовало бы обхода раннего OTP/fuse floorsweep и
не следует из этого результата.

Код старой версии probe был `2` только из-за необязательных ответов:
`GET_PHYS_GPC_MASK` вернул `NV_ERR_INSUFFICIENT_PERMISSIONS`, а шесть
`GET_TPC_RECONFIG_MASK` — `NV_ERR_NOT_SUPPORTED`. Все обязательные запросы
прошли; критерий exit code после этого прогона исправлен. Доказательства:
`../out/rm-topology-cmp70hx.json`, `nvidia-smi-q.txt`, `lspci.txt`, `uname.txt`
и `usb-log-linux-rm-r0.txt`.
