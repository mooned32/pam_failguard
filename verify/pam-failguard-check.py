#!/usr/bin/env python3
"""
Проверка pam_failguard: отказ в приёме пароля на N секунд после неудачи.

Проверяем:
  * неверный пароль            -> отказ
  * верный пароль сразу после  -> ОТКАЗ (это и есть требование)
  * повторный отказ            -> отказ, окно скользит
  * верный пароль после окна   -> вход
  * неудача на просроченном состоянии -> засчитывается
    (предпоследний шаг - регрессия: раньше просроченный файл состояния
    удалялся, а запись уходила в уже удалённый файл, и неудача терялась)
  * sudo, неверный + сразу верный -> отказ
    (sudo передаёт PAM_SILENT при каждом запросе пароля; раньше модуль
    пропускал такие вызовы и для sudo не работал вообще)

Отказ наступает ПОСЛЕ проверки пароля - этого требует unity-greeter,
см. README, - поэтому его время сравнимо с обычной попыткой. Проверяется
исход и отсутствие зависания на delay секунд.
"""

import os
import pty
import select
import subprocess
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


def attempt_sudo(pws, timeout=45):
    """Несколько попыток sudo подряд -> (секунды, вошел_ли).

    Пароли отдаются на вход (sudo -S). sudo передаёт PAM флаг PAM_SILENT -
    именно этот путь и должен учитывать модуль.
    """
    t0 = time.time()
    p = subprocess.Popen(
        ["sudo", "-S", "-k", "-p", "PWD:", "id", "-un"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)
    try:
        p.communicate(input=("\n".join(pws) + "\n").encode(), timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        p.communicate()
    return time.time() - t0, p.returncode == 0


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

    # Регрессия: неудача приходит, когда в файле состояния лежит ПРОСРОЧЕННАЯ
    # запись. Прежняя версия в этот момент удаляла файл и писала в удалённый
    # дескриптор - запись терялась, и следующий верный пароль принимался.
    time.sleep(delay + 1)
    el, ok = attempt(user, "wrongpass3")
    check("7) неверный после паузы -> отказ", el, ok, False)
    el, ok = attempt(user, good)
    check("8) ВЕРНЫЙ сразу -> отказ (просроченное состояние учтено)", el, ok, False)

    # sudo передаёт PAM_SILENT при каждом запросе пароля. Раньше модуль
    # пропускал такие вызовы, и для sudo он не работал вовсе: неудача не
    # засчитывалась, отказа не было. Здесь это проверяется.
    print("\nПроверка sudo (sudo зовёт PAM с флагом PAM_SILENT):")
    time.sleep(delay + 1)
    el, ok = attempt_sudo(["wrongpass", good, "x"])
    check("9) неверный, затем ВЕРНЫЙ сразу -> отказ", el, ok, False)
    time.sleep(delay + 1)
    el, ok = attempt_sudo([good])
    check("10) ВЕРНЫЙ после паузы -> вход", el, ok, True)

    print()
    if fails:
        print("НЕ ПРОЙДЕНО: %s" % "; ".join(fails))
        sys.exit(1)
    print("ВСЁ ПРОЙДЕНО: отказ работает, окно ровно %d с, вход после окна проходит." % delay)
