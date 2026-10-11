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
sudo python3 src/tools/nv-rm-topology.py --tinygrad /path/to/tinygrad \
  | tee rm-topology-cmp70hx.json
```

Если CMP не является первым NVIDIA GPU, укажите `--index N`. Другой commit
tinygrad отклоняется; `--allow-unpinned` предназначен только для осознанной
проверки совместимости структур. Код возврата `0` означает, что все запросы
ответили; `2` сохраняет частичный JSON, но означает отказ хотя бы одной
команды.

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
