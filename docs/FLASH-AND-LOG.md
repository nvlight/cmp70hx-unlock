# Запись загрузчика и снятие журнала

## Development-бинарник

Подключите только нужный USB-носитель и из корня проекта запустите:

```powershell
powershell -ExecutionPolicy Bypass -File out\flash-build.ps1
```

Для отдельного read-only опыта топологии сначала соберите
`GR_TOPOLOGY=1`, затем используйте явный режим:

```powershell
powershell -ExecutionPolicy Bypass -File out\flash-build.ps1 -TopologyProbe
```

Этот режим требует маркеры `GRTOPO` внутри EFI, но не меняет release-эталон
и не требует `-AllowNewBuild`. Обычный запуск без `-TopologyProbe` по-прежнему
записывает только проверенный `unlock_v3r.efi`.

Скрипт проверяет MD5, размер, профиль CMP 70HX и обязательные UTF-16-маркеры,
удаляет старый `EFI\BOOT\BOOTX64.EFI`, записывает новый и сверяет содержимое.
При неоднозначном поиске укажите `-Stick X:`. `-AllowNewBuild` допустим только
для заранее запланированного экспериментального MD5.

Текущий release-эталон: `3C076AF7CF7C2BDA65FDA01F7678982C`, 680960 байт.

## Релизный образ

```powershell
powershell -ExecutionPolicy Bypass -File out\make-image.ps1 -Version 1.0.1
powershell -ExecutionPolicy Bypass -File out\verify-image.ps1
```

Готовый `.img` записывает человек через Rufus DD/Etcher. Скрипты проекта не
перезаписывают целый реальный диск автоматически.

## Перед загрузкой

Обязательно очистите старую область raw-журнала:

```powershell
out\reset-stick-log.ps1
```

Образ заканчивается раньше LBA 4 000 000, поэтому повторная запись `.img` не
удаляет журнал прошлого запуска. Без очистки можно получить ложный PASS.

Затем человек перезагружает машину, выбирает USB в UEFI boot-меню и не
прерывает прогон. Агент не выполняет reboot/F12 и не обесточивает стенд.

## После загрузки

```powershell
out\pull-log.ps1 -Tag <короткая-метка>
out\verify-log.ps1 out\usb-log-<метка>.txt
out\verify-image.ps1 -CompareOnly
```

Не используйте `-NoSave` для доказательного прогона. Сохраните лог даже при
FAIL: отрицательный результат нужен для истории.

Проверяйте в таком порядке:

1. последний маркер `END   ---- end of log ----` присутствует;
2. профиль — CMP 70HX GA104, `10de:248a`, 8 ГБ;
3. две render-маски открыты последовательно;
4. `GFX_SPEED_SELECT=0x4` подтверждён readback;
5. SS0=`0x88888888`, SS1=`0x00000008`, PLM=`0xFFFFFFFF`;
6. `verify-log.ps1` вернул код 0;
7. загруженный USB совпал с образом/EFI через `-CompareOnly`.

Полный формат: [`LOGGING.md`](LOGGING.md). Историческая расширенная процедура:
[`history/FLASH-AND-LOG.md`](history/FLASH-AND-LOG.md).
