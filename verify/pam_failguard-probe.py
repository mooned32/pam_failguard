#!/usr/bin/env python3
"""
Проверка pam_failguard с произвольными deny/delay.

Использование: pam_failguard-probe.py <user> <pass> <deny> <delay> [rec_delay]

rec_delay - если задан, у строки record своё значение delay (для проверки,
что будет при расхождении строк).
"""
import os
import pty
import select
import sys
import time


def attempt(user, pw, timeout=45):
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


def show(label, el, ok):
    print("  %-46s %5.2f с  %s" % (label, el, "ВОШЁЛ" if ok else "ОТКАЗАНО"))


if __name__ == "__main__":
    user = sys.argv[1]
    good = sys.argv[2]
    deny = int(sys.argv[3])
    delay = int(sys.argv[4])

    print("deny=%d delay=%d" % (deny, delay))
    print("Ожидание: отказ включается после %d неудач, окно живёт %d с\n" % (deny, delay))

    el, ok = attempt(user, good)
    show("верный пароль, чистое состояние", el, ok)

    for n in range(1, deny + 1):
        el, ok = attempt(user, "wrong%d" % n)
        show("неудача #%d" % n, el, ok)

    # после deny неудач верный пароль обязан отказать
    el, ok = attempt(user, good)
    show("верный сразу после %d неудач (ожидаем отказ)" % deny, el, ok)

    el, ok = attempt(user, good)
    show("верный ещё раз (ожидаем отказ)", el, ok)

    time.sleep(delay + 1)
    el, ok = attempt(user, good)
    show("верный после паузы %d с (ожидаем вход)" % (delay + 1), el, ok)