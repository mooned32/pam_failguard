# Настройка PAM: что нужно сделать на чистой системе

Документ описывает настройку с нуля: что собрать, куда положить и какие
правки внести в `/etc/pam.d/common-auth`. Сторонние файлы, не относящиеся к
PAM, в схеме не участвуют и при настройке не трогаются.

Требуется только: исходник модуля и штатный компилятор. Никаких дополнительных
пакетов — `libpam0g-dev` не нужен.

---

## Куда всё кладётся

| Что | Куда |
|---|---|
| `pam_failguard.so` | `/lib/<triplet>/security/` — каталог модулей PAM |
| правки в конфиг | `/etc/pam.d/common-auth` — правится на месте, файл целиком не подменяется |
| состояние | `/var/lib/pam-failguard/` — создаёт сам модуль, руками не нужно |

`<triplet>` — `i386-linux-gnu` или `x86_64-linux-gnu`, в зависимости от
архитектуры. Makefile определяет его сам по расположению `libpam.so.0`.

## Установка модуля

```sh
make install
```

Собирает модуль и кладёт его в каталог модулей PAM. Больше ничего не делает —
конфиг правится отдельно, вручную (следующий раздел). Нужен только штатный
компилятор, `libpam0g-dev` не требуется.

Откат:

```sh
make uninstall
```

Собирать нужно **на целевой системе**, под её архитектуру: скопированный с
другой машины `.so` загрузчик не примет. Переносить следует исходник.

Модуль не линкуется с `libpam` — из неопределённых символов у него только
`pam_get_user` и `pam_syslog`, они разрешаются при загрузке из `libpam.so.0`
того процесса, который его подгружает. Реальная зависимость одна — `libc`.

## Три правки в `/etc/pam.d/common-auth`

Правьте **собственный** `common-auth` этой системы. Снимок из `etc/pam.d/`
подставлять целиком не следует: при другой версии `pam-auth-update` перезапись
уничтожит штатное содержимое файла. Диф ниже от версии не зависит.

```diff
 # here are the per-package modules (the "Primary" block)
-auth	[success=1 default=ignore]	pam_unix.so nullok_secure
+auth	[success=2 default=ignore]	pam_unix.so nullok_secure
+auth optional pam_failguard.so record deny=1 delay=10
 # here's the fallback if no module succeeds
 auth	requisite			pam_deny.so
 # prime the stack with a positive return value if there isn't one already;
@@ -23,3 +24,6 @@
 auth	required			pam_permit.so
 # and here are more per-package modules (the "Additional" block)
 # end of pam-auth-update config
+
+# pam-failguard: отказ в приёме пароля на 10 с после 1 неудачной попытки
+auth required pam_failguard.so refuse deny=1 delay=10
```

Итого: одна замена флага, одна строка вставлена после `pam_unix`, две
добавлены в конец.

## Ничего больше

Запись в `auth.log` идёт через `pam_syslog()` в facility `auth` — настраивать
нечего. Сервисные файлы вроде `lightdm`, `sudo`, `su`, `login`, `sshd`
править не нужно: механизм заработает на всех, кто подключает `common-auth`.

---

## Итоговый auth-стек

```
auth	[success=2 default=ignore]	pam_unix.so nullok_secure
auth optional pam_failguard.so record deny=1 delay=10
auth	requisite			pam_deny.so
auth	required			pam_permit.so
auth required pam_failguard.so refuse deny=1 delay=10
```

Путь исполнения:

| Событие | Что происходит |
|---|---|
| пароль верен, окно не истекло | `pam_unix` → успех, прыжок через `record` и `pam_deny` → `pam_permit` → `refuse` **отказывает** |
| пароль верен, окно истекло | `pam_unix` → успех → `pam_permit` → `refuse` пропускает → **вход** |
| пароль неверен | `pam_unix` → `default=ignore` → `record` **пишет метку времени** → `pam_deny` → **отказ** |
| пароль неверен, окно было активно | то же плюс `record` обновляет метку — окно продлевается |

### Зачем `success=2` вместо `success=1`

Флаг у `pam_unix` означает «при успехе перепрыгнуть N модулей вперёд».
Было `success=1` — перепрыгивался только `pam_deny`. Стало `success=2` —
перепрыгиваются `record` и `pam_deny`, поэтому при успехе стек попадает на
`pam_permit`, а `refuse` остаётся последним и может отказать.

Счётчик в `success=N` относительный, поэтому добавление модулей **перед**
`pam_unix` его не ломает.

### Почему `refuse` стоит после `pam_permit`

Отказ обязан происходить после того, как PAM запросил пароль. В
`unity-greeter` (`src/greeter-list.vala`, строки 776/803/859/870) флаг
`prompted` выставляется только когда диалог PAM реально запросил пароль:

```vala
if (prompted)  show_message (_("Invalid password, please try again"), true);
else           show_message (_("Failed to authenticate"), true);
```

Если отказать до `pam_unix`, диалог не вызывается, `prompted` остаётся
`false`, и окно входа показывает аварийный экран с кнопкой **Retry** вместо
обычного сообщения. Разместить `refuse` раньше в стеке нельзя: прыжок
`success=2` перепрыгнул бы и его, а `pam_deny` пришлось бы убрать — тогда
при неудачной проверке пароля стек доходил бы до `pam_permit` и **выдавал
доступ**.

---

## Параметры

| Параметр | Значение | Смысл |
|---|---|---|
| `delay=10` | 10 **секунд** | столько длится отказ. Намеренно отличается от `pam_faildelay`, где `delay` в микросекундах |
| `deny=1` | 1 неудача | сколько неудачных попыток включает отказ |
| `record` | режим | писать метку времени, только при неудаче |
| `refuse` | режим | проверять окно и отказывать, только после успешной проверки |

Оба вызова несут оба параметра — так конфигурация читается целиком в любой
из двух строк. Для произвольных значений правится только текст этих строк.

## Службы, которые покрываются этой настройкой

`common-auth` подключают через `@include`, поэтому правка действует сразу на
все способы входа, без изменений в сервисных файлах:

| Сервис | `@include common-auth` |
|---|---|
| `sudo` | да |
| `lightdm` (окно входа) | да |
| `gnome-screensaver` (блокировка экрана) | да |
| `su` | да |
| `login` | да |
| `sshd` | да |
| `lightdm-greeter` | нет — это собственная сессия greeter, пароль там не вводится |

---

## Откат

```sh
make uninstall                                   # убрать модуль
sudo rm -rf /var/lib/pam-failguard               # убрать состояние
```

Три правки в `common-auth` отменяются вручную — диф выше в обратную сторону.

`common-auth.pristine` для отката не требуется: он не входит в схему
настройки, а служит снимком исходного файла, на котором показан диф.

---

## Файлы проекта

| Путь | Роль в настройке |
|---|---|
| `src/pam_failguard.c` | **нужен** — исходник, из него собирается модуль |
| `Makefile` | необязателен, тот же самый вызов `cc` |
| `etc/pam.d/common-auth` | справочно: итоговое состояние `common-auth` |
| `etc/pam.d/common-auth.pristine` | справочно: исходное состояние, база для диффа |
| `verify/pam-failguard-check.py` | необязательно: проверка после настройки |