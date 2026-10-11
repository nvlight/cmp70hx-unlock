# Ограничения рендера CMP 70HX

Карта работает на 30 SM / 3840 CUDA cores, 1545 МГц и 256-битной памяти.
Анлок снимает issue-rate и render selector, но не расширяет физическую
конфигурацию. Лучший подтверждённый режим — `GFX_SPEED_SELECT=0x4`,
50 fps / 135 Вт в зафиксированном Cyberpunk 2077 benchmark.

`FEAT_READOUT_0.bit8` не используется как критерий полного PGRAPH: нулевое
значение наблюдается и на полноценной RTX 3090. Доступность API, полнота
доступного 30-SM GR, физическая топология и RT/media проверяются раздельно.
Драйверный A/B-эксперимент R0–R3 закрыт отрицательно: Full дал 52,057 fps
против R0=52,056 fps. Подробности: [`GR-DRIVER-PATCH.md`](GR-DRIVER-PATCH.md).

Методика текущих замеров: [`GAME-BENCH-LOG.md`](GAME-BENCH-LOG.md). Полный план
и закрытые гипотезы: [`history/RENDER-LIMITS.md`](history/RENDER-LIMITS.md).
