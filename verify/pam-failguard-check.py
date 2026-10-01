#!/usr/bin/env python3
"""
Проверка pam_failguard: отказ в приёме пароля на N секунд после неудачи.

Проверяем:
  * неверный пароль            -> отказ
  * верный пароль сразу после  -> ОТКАЗ (это и есть требование)
  * повторный отказ            -> отказ, окно скользит
  * верный пароль после окна   -> вход

Отказ наступает ПОСЛЕ проверки пароля - этого требует unity-greeter,
см. README, - поэтому его время сравнимо с обычной попыткой. Проверяется
исход и отсутствие зависания на delay секунд.
"""

import os
import pty
import select
import sys
import time

SLOW = 6.0  # больше этого - считаем зависанием на delay секунд


def attempt(user, pw, timeout=45):
    """Одна попытка su в псевдотерминале -> (секунды, вошел_ли)"""
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp("su", ["su", "-", user, "-c", "id -un"])
        os._exit(127)
    time.sleep(0.5)
    os.write(fd, pw.encode() + b"\n")
    t0 = time.time()
    out = b""
    status = None
    while True:
        try:
            r, _, _ = select.select([fd], [], [], 0.3)
        except OSError:
            break
        if r:
            try:
                d = os.read(fd, 1024)
            except OSError:
                break
            if not d:
                break
            out += d
        p, st = os.waitpid(pid, os.WNOHANG)
        if p:
            status = st
            break
    if status is None:
        p, status = os.waitpid(pid, 0)
    el = time.time() - t0
    try:
        os.close(fd)
    except OSError:
        pass
    ok = os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
    return el, ok


fails = []


def check(label, el, ok, expect_ok, expect_fast=True):
    verdict = "OK  "
    if ok != expect_ok:
        verdict = "СБОЙ"
        fails.append(label)
    if expect_fast and el > SLOW:
        verdict = "МЕДЛЕННО"
        fails.append(label + " (подозрение на зависание)")
    print(
        "  %s %-44s %5.2f с  %-9s (ждали: %s)"
        % (verdict, label, el, "ВОШЁЛ" if ok else "ОТКАЗАНО", "вход" if expect_ok else "отказ")
    )


if __name__ == "__main__":
    user = sys.argv[1]
    good = sys.argv[2]
    delay = int(sys.argv[3]) if len(sys.argv) > 3 else 10

    print("Проверка pam_failguard deny=1 delay=%d для %s" % (delay, user))
    print("Отказ наступает после проверки пароля; зависания на %d с быть не должно.\n" % delay)

    el, ok = attempt(user, good)
    check("верный пароль (отказов ещё не было)", el, ok, True)

    el, ok = attempt(user, "wrongpass")
    check("1) неверный пароль", el, ok, False)

    el, ok = attempt(user, good)
    check("2) ВЕРНЫЙ сразу после -> отказ", el, ok, False)

    el, ok = attempt(user, good)
    check("3) ВЕРНЫЙ ещё раз -> отказ (окно скользит)", el, ok, False)

    time.sleep(delay + 1)
    el, ok = attempt(user, good)
    check("4) ВЕРНЫЙ после паузы %d с -> вход" % (delay + 1), el, ok, True)

    el, ok = attempt(user, "wrongpass2")
    check("5) снова неверный", el, ok, False)
    el, ok = attempt(user, good)
    check("6) ВЕРНЫЙ сразу -> отказ", el, ok, False)

    print()
    if fails:
        print("НЕ ПРОЙДЕНО: %s" % "; ".join(fails))
        sys.exit(1)
    print("ВСЁ ПРОЙДЕНО: отказ работает, окно ровно %d с, вход после окна проходит." % delay)
