CC      ?= cc
CFLAGS  ?= -Wall -O2 -fPIC
TARGET   = pam_failguard.so
SRC      = src/pam_failguard.c

# Каталоги установки. PAM ищет модуль по нескольким путям, и набор путей
# зависит от того, как процесс-владелец подключил libpam:
#
#   $(PAMDIR)   каталог модулей штатной библиотеки PAM (multiarch), его
#               используют sshd, su, sudo, login;
#   /lib/security
#               путь, который проверяет compiz - именно он аутентифицирует
#               разблокировку экрана в Ubuntu 15.10 (Unity). Без копии
#               здесь на экране блокировки получаем
#               "PAM unable to dlopen(pam_failguard.so)".
#
# Ставим в оба: лишняя копия в 12 КБ не мешает, а блокировка работает.
PAMDIR  ?= $(shell dirname "$$(ldconfig -p | grep -m1 -oE '/[^ ]*libpam\.so\.0')")/security
PAMDIRS ?= $(PAMDIR) /lib/security

# Модуль ОБЯЗАН быть линкован с libpam, иначе он не загрузится там, где
# процесс-владелец не линкует libpam сам.
#
# Символы pam_get_user/pam_syslog не определялись при загрузке: модуль
# полагался на то, что они окажутся в глобальной области процесса,
# который его подгружает. Для sshd/su/sudo это верно (они линкуют -lpam),
# а для compiz — нет: он обращается к PAM через dlopen, и в его области
# libpam.so.0 не глобальна. На экране блокировки Unity результат:
#
#   PAM unable to dlopen(pam_failguard.so): undefined symbol: pam_syslog
#
# Линкуем по версионному soname (-l:libpam.so.0), а не через -lpam:
# последнему нужен libpam0g-dev, а он на целевой системе может отсутствовать.
# Собственных зависимостей у модуля по-прежнему только libc и libpam.
LDFLAGS ?= -l:libpam.so.0

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -shared -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	@for d in $(PAMDIRS); do \
	    mkdir -p "$$d" && install -m 644 $(TARGET) "$$d/$(TARGET)" \
	        && echo "установлен в $$d" \
	        || echo "НЕ УСТАНОВЛЕН в $$d (проверьте путь вручную)" >&2; \
	done

uninstall:
	@for d in $(PAMDIRS); do rm -f "$$d/$(TARGET)"; done
	rm -rf /var/lib/pam-failguard

.PHONY: all clean install uninstall