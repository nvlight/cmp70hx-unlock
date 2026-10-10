# Разбор драйвера 610.43.03 — итог

Разбор подтвердил структуру команды FRTS, формулу `WPR2_LO = frts >> 8` и
раскладку `DMAP`. Ошибка порта заключалась не в `gfwImageSize`, а в пропущенной
`kgspGetWprEndMargin`; для 70HX рабочей оказалась маржа 128 МиБ.

Текущая геометрия приведена в [`STATUS.md`](STATUS.md), карта регистров — в
[`REGISTERS.md`](REGISTERS.md). Полный побайтовый разбор сохранён в
[`history/70HX-DRIVER-ANALYSIS.md`](history/70HX-DRIVER-ANALYSIS.md).
