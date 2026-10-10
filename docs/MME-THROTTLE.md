# Проверка MME throttle

Направление закрыто отрицательно для исследованного Windows-драйвера 616.92:
паттерн `CALL_MME_MACRO` со счётчиком 240, описанный для CMP 40HX, отсутствует.
Переносить вывод Turing/Linux на GA104/Windows нельзя.

Полный анализ ELF/драйвера: [`history/MME-THROTTLE.md`](history/MME-THROTTLE.md).
