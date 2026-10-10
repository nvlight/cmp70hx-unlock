# Карта ключевых регистров CMP 70HX

Все адреса — BAR0 MMIO, если не указано `cfg`.

## Compute и WPR2

| Адрес | Назначение | Рабочее значение |
|---|---|---|
| `0x001FA824` | WPR2_LO | зависит от стадии; ожидаемое FRTS `0x01F7E000` |
| `0x001FA828` | WPR2_HI | `0x01F7EE00` при установке окна |
| `0x001FA7CC` | WPR2 privilege mask | защищает WPR2 |
| `0x00823804` | PLM страницы SS | `0xFFFFFFFF` |
| `0x0082381C` | SS0 | `0x88888888` |
| `0x00823820` | SS1 | `0x00000008` |
| `0x00504204` | issue-rate modifier | `0x00000005` после анлока |

## Render

| Адрес | Назначение | Рабочее значение |
|---|---|---|
| `0x00823800` | маска страницы GFX selector | `0xFFFFFFFF` |
| `0x00823B04` | вторая необходимая render-маска | `0xFFFFFFFF` |
| `0x00823830` | GFX_SPEED_SELECT | `0x00000004` |

Release-цикл открывает ровно две render-маски. Старые XVE/XP3G адреса были
исключены из release-списка после аппаратного A/B.

## PCIe

| Регистр | Значение/роль |
|---|---|
| BAR0 `0x880A8` | зеркало LC2/TLS, отдельный protected domain |
| BAR0 `0x8841C` | PRIV_MISC_1 policy |
| BAR0 `0x8C040` | LINK_CONFIG_0 / MAX_RATE |
| BAR0 `0x8E110..0x8E12C` | XP3G override/value policy |
| cfg `cap+0x10` | LNKCTL, bit Retrain Link |
| cfg `cap+0x2C` | LNKCAP2, read-only |
| cfg `cap+0x30` | LNKCTL2, Target Link Speed |
| cfg `cap+0x32` | LNKSTA2, read-only |

Capability Pointer читается по cfg offset `0x34`. TLS=2 был подтверждён на GPU
и bridge, но LNKSTA остался Gen1 x4; см. [`STATUS.md`](STATUS.md).

## Эмпирические правила

- нужные selector/mask значения переживают FLR рабочего цикла;
- POST/VBIOS reinit уничтожает анлок;
- закрытые PLM-страницы молча отбрасывают host write;
- точный readback нужен, но сам по себе не доказывает производительность.

Полная прежняя таблица: [`history/REGISTERS.md`](history/REGISTERS.md).
