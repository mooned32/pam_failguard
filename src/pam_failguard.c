/*
 * pam_failguard.so - модуль PAM: отказ в приёме пароля на заданное время
 *                    после неудачной попытки.
 *
 * ЗАДАЧА
 *   После неудачной попытки ввода пароля система должна:
 *     - сразу показать обычное сообщение о неверном пароле (ничего не "висит");
 *     - следующие N секунд не принимать НИКАКОЙ пароль вообще, даже верный;
 *     - по истечении N секунд вести себя как обычно.
 *
 * ОТЛИЧИЕ ОТ pam_faildelay
 *   Штатный pam_faildelay реализует паузу через select() внутри libpam и
 *   обрывает её сигналом, поэтому заданные 10 секунд превращаются в 6-9.
 *   Кроме того он "ждёт": экран не отвечает 10 секунд, и только потом
 *   появляется сообщение об ошибке. Здесь же паузы нет вообще: модуль
 *   возвращает PAM_AUTH_ERR ДО проверки пароля, то есть отказывает.
 *
 * ЕДИНИЦЫ
 *   delay задаётся в СЕКУНДАХ (delay=10 = 10 секунд). Это намеренно
 *   отличается от pam_faildelay, где delay=10000000 означает микросекунды.
 *
 * ПРИМЕНЕНИЕ В СТЕКЕ
 *   Модуль нужен дважды: результат проверки пароля модулю, стоящему ДО
 *   неё, недоступен, поэтому "записать неудачу" и "отказать" разнесены.
 *
 *     auth  [success=2 default=ignore]  pam_unix.so nullok_secure
 *     auth  optional   pam_failguard.so record deny=1 delay=10
 *     auth  requisite  pam_deny.so
 *     auth  required   pam_permit.so
 *     auth  required   pam_failguard.so refuse deny=1 delay=10
 *
 *   record - после pam_unix с default=ignore, поэтому выполняется ТОЛЬКО
 *            при неудаче и записывает метку времени.
 *   refuse - в конце стека, срабатывает только после УСПЕШНОЙ проверки
 *            пароля: если окно не истекло, вход всё равно отклоняется.
 *
 * ПОЧЕМУ ОТКАЗ ПОСЛЕ ПРОВЕРКИ ПАРОЛЯ, А НЕ ДО НЕЁ
 *   unity-greeter (src/greeter-list.vala) держит флаг prompted, который
 *   выставляется ТОЛЬКО когда PAM реально запросил пароль. Если стек
 *   отказывает до pam_unix, диалог не вызывается, prompted остаётся
 *   false, и greeter показывает аварийный экран "Failed to authenticate"
 *   с кнопкой Retry вместо обычного "Invalid password, please try again".
 *   Поэтому проверка пароля идёт первой, а отказ - последним модулем.
 *
 *   check  - стоит перед pam_unix, отказывает, если была недавняя неудача.
 *   record - стоит после pam_unix с default=ignore, поэтому выполняется
 *            ТОЛЬКО при неудаче и записывает метку времени.
 *
 * СОСТОЯНИЕ
 *   /var/lib/pam-failguard/<пользователь>  содержит "счётчик время".
 *   Состояние самоустаревает: если между попытками прошло больше delay,
 *   счётчик обнуляется, а просроченный файл удаляется. Поэтому ничего
 *   не накапливается, не переживает перезагрузку и не требует
 *   ручной разблокировки.
 *
 * ОТКАЗ ПОД ВРЕМЕНЕМ (скользящее окно)
 *   Каждый отказ заново отсчитывает delay секунд, поэтому непрерывный
 *   перебор держится бесконечно. Счётчик неудач при этом на длину отказа
 *   не влияет: она всегда ровно delay секунд и не растёт.
 *
 * ОТКАЗОУСТОЙЧИВОСТЬ
 *   Любая ошибка ввода-вывода трактуется как "открыть": модуль возвращает
 *   PAM_IGNORE и не препятствует входу. Сломавшийся каталог состояния
 *   не должен запирать учётные записи. Исключение - часы, ушедшие назад:
 *   тогда метка считается просроченной (тоже открыть), иначе учётку
 *   заблокировало бы на время разницы.
 *
 * СБОРКА
 *   gcc -Wall -O2 -fPIC -shared -o pam_failguard.so pam_failguard.c
 *   (достаточно штатного gcc, libpam0g-dev не требуется)
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>

/* ------------------------------------------------------------------ *
 * Минимальные объявления ABI Linux-PAM.
 * libpam0g-dev в системе нет, а ставить пакеты ради заголовков не
 * нужно: структуры и константы Linux-PAM стабильны, а нужно их всего три.
 * ------------------------------------------------------------------ */
#define PAM_EXTERN extern

typedef struct pam_handle pam_handle_t;

#define PAM_SUCCESS        0
#define PAM_BUF_ERR        5
#define PAM_AUTH_ERR       7
#define PAM_IGNORE        25

#define PAM_SILENT      0x8000

extern int  pam_get_user(pam_handle_t *pamh, const char **user, const char *prompt);
extern void pam_syslog(const pam_handle_t *pamh, int priority, const char *format, ...);

#define STATE_DIR "/var/lib/pam-failguard"
#define USERNAME_MAX 256
#define PATH_MAX_LEN 512      /* STATE_DIR + USERNAME_MAX + разделитель */

/* значения по умолчанию */
#define DEFAULT_DENY  1
#define DEFAULT_DELAY 10      /* секунд */

enum mode { MODE_RECORD, MODE_REFUSE };

struct options {
    enum mode mode;
    long deny;
    long delay;               /* секунды */
    int  debug;
};

struct state {
    long count;               /* неудач в пределах окна delay */
    long last;                /* время последней попытки (unix time) */
    int  existed;             /* был ли файл состояния */
};

static void
log_msg(pam_handle_t *pamh, int priority, const char *fmt, ...)
{
    va_list ap;
    char buf[512];

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    pam_syslog(pamh, priority, "%s", buf);
}

/* разбор аргументов модуля. 0 - ошибка, 1 - ок */
static int
parse_args(int argc, const char **argv, struct options *o)
{
    int i;

    o->mode  = MODE_REFUSE;   /* если слово не указано - считаем refuse */
    o->deny  = DEFAULT_DENY;
    o->delay = DEFAULT_DELAY;
    o->debug = 0;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "refuse") == 0) {
            o->mode = MODE_REFUSE;
        } else if (strcmp(argv[i], "record") == 0) {
            o->mode = MODE_RECORD;
        } else if (strncmp(argv[i], "deny=", 5) == 0) {
            char *end = NULL;
            long v = strtol(argv[i] + 5, &end, 10);
            if (end == argv[i] + 5 || (end && *end != '\0') || v < 0) {
                return 0;
            }
            o->deny = v;
        } else if (strncmp(argv[i], "delay=", 6) == 0) {
            char *end = NULL;
            long v = strtol(argv[i] + 6, &end, 10);
            if (end == argv[i] + 6 || (end && *end != '\0') || v <= 0) {
                return 0;   /* delay должен быть положительным */
            }
            o->delay = v;
        } else if (strcmp(argv[i], "debug") == 0) {
            o->debug = 1;
        } else {
            return 0;       /* неизвестный аргумент */
        }
    }
    return 1;
}

/* безопасно ли использовать имя пользователя как имя файла */
static int
usable_name(const char *name)
{
    size_t i;

    if (name == NULL || name[0] == '\0')
        return 0;
    if (strlen(name) >= USERNAME_MAX)
        return 0;
    for (i = 0; name[i] != '\0'; i++) {
        if (name[i] == '/' || name[i] == '\\')
            return 0;
    }
    return 1;
}

static int
open_state(const char *name, char *path, size_t pathlen)
{
    if (snprintf(path, pathlen, "%s/%s", STATE_DIR, name) >= (int)pathlen)
        return -1;
    return open(path, O_RDWR | O_CREAT, 0600);
}

static int
read_state(int fd, struct state *st)
{
    char buf[64];
    ssize_t n;

    st->count = 0;
    st->last = 0;
    st->existed = 0;

    if (lseek(fd, 0, SEEK_SET) == (off_t)-1)
        return 0;

    n = read(fd, buf, sizeof(buf) - 1);
    if (n <= 0)
        return 0;
    buf[n] = '\0';

    if (sscanf(buf, "%ld %ld", &st->count, &st->last) != 2)
        return 0;

    st->existed = 1;
    return 1;
}

static int
write_state(int fd, const struct state *st)
{
    char buf[64];
    int n;

    n = snprintf(buf, sizeof(buf), "%ld %ld\n", st->count, st->last);
    if (n < 0 || n >= (int)sizeof(buf))
        return 0;
    if (ftruncate(fd, 0) == -1)
        return 0;
    if (lseek(fd, 0, SEEK_SET) == (off_t)-1)
        return 0;
    if (write(fd, buf, (size_t)n) != n)
        return 0;
    return 1;
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    const char *username = NULL;
    struct options o;
    struct state st;
    char path[PATH_MAX_LEN];
    long now;
    int fd;
    int ret = PAM_IGNORE;

    if (!parse_args(argc, argv, &o)) {
        log_msg(pamh, LOG_ERR,
                "pam_failguard: invalid module arguments, authentication not restricted");
        return PAM_IGNORE;   /* не блокируем вход из-за ошибки конфигурации */
    }

    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS ||
        !usable_name(username)) {
        return PAM_IGNORE;
    }

    if (flags & PAM_SILENT) {
        /* Служебный вызов БЕЗ запроса пароля: пользователь ничего не вводил,
         * значит неудачной попытки не было и засчитывать её нельзя.
         *
         * gnome-screensaver при блокировке экрана (Win+L) делает именно
         * такой вызов, проверяя пользователя, и повторяет его, пока экран
         * заблокирован. Без этой проверки каждая служебная проверка
         * засчитывалась как неудача и открывала окно отказа ровно в тот
         * момент, когда пользователь начинает вводить пароль, а следующая
         * проверка его продлевала. Из-за этого разблокировать экран было
         * невозможно вовсе. */
        if (o.debug) {
            log_msg(pamh, LOG_DEBUG,
                    "pam_failguard: PAM_SILENT call for user [%s], ignored",
                    username);
        }
        return PAM_IGNORE;
    }

    now = (long)time(NULL);

    if (mkdir(STATE_DIR, 0700) == -1 && errno != EEXIST) {
        log_msg(pamh, LOG_WARNING,
                "pam_failguard: cannot create %s (%s), authentication not restricted",
                STATE_DIR, strerror(errno));
        return PAM_IGNORE;
    }

    fd = open_state(username, path, sizeof(path));
    if (fd < 0) {
        log_msg(pamh, LOG_WARNING,
                "pam_failguard: cannot open state file (%s), authentication not restricted",
                strerror(errno));
        return PAM_IGNORE;
    }
    if (flock(fd, LOCK_EX) == -1) {
        /* не блокируем вход из-за проблем с блокировкой файла */
        close(fd);
        return PAM_IGNORE;
    }

    if (!read_state(fd, &st)) {
        st.count = 0;
        st.last = 0;
        st.existed = 0;
    }

    /* состояние просрочено: часы ушли назад либо давно не было попыток.
       Сбрасываем и удаляем - так состояние самоочищается. */
    if (st.existed && (st.last > now || (now - st.last) >= o.delay)) {
        st.count = 0;
        st.last = 0;
        st.existed = 0;
        if (unlink(path) == -1 && errno != ENOENT) {
            /* файл не удалился - не критично, значения уже сброшены */
        }
    }

    if (o.mode == MODE_RECORD) {
        /* сюда попадаем только при неудачной проверке пароля */
        st.count += 1;
        st.last = now;
        if (!write_state(fd, &st)) {
            log_msg(pamh, LOG_WARNING, "pam_failguard: cannot write state file");
        } else if (o.debug) {
            log_msg(pamh, LOG_DEBUG,
                    "pam_failguard: recorded failure #%ld for user [%s]",
                    st.count, username);
        }
        ret = PAM_IGNORE;
    } else {
        /* MODE_REFUSE: сюда попадаем только после УСПЕШНОЙ проверки пароля,
           то есть диалог PAM уже отработал и greeter знает, что пароль
           спрашивали. Отказываем здесь - иначе greeter покажет аварийный
           экран "Failed to authenticate" вместо обычного сообщения. */
        if (st.existed && st.count >= o.deny && st.last > 0) {
            long left = o.delay - (now - st.last);

            if (left < 1)
                left = 1;

            /* Окно НЕ продлевается: отказ отсчитывается от последней
             * НЕУДАЧНОЙ попытки, записанной модулем record.
             *
             * Продление здесь было бы самоочевидной, но ломающей ошибкой:
             * верный пароль не является неудачной попыткой, поэтому сдвигать
             * из-за него таймер нельзя. Диалог блокировки экрана
             * (gnome-screensaver) повторяет проверку каждые 3 секунды и имеет
             * жёсткий предел MAX_FAILURES=5 попыток, после которого окно
             * закрывается вовсе. С продлением окно не истекало никогда, пока
             * пользователь продолжал жать Enter, и разблокировать экран
             * становилось невозможно - приходилось выходить и входить через
             * основное окно входа.
             *
             * Скользящее окно при этом сохраняется: каждая новая неудачная
             * попытка обновляет метку в модуле record. */
            log_msg(pamh, LOG_NOTICE,
                    "pam_failguard: authentication refused for user [%s], %ld failed logins, "
                    "%ld s remaining",
                    username, st.count, left);
            ret = PAM_AUTH_ERR;
        } else {
            if (o.debug) {
                log_msg(pamh, LOG_DEBUG,
                        "pam_failguard: no refusal for user [%s] (%ld failed logins)",
                        username, st.count);
            }
            ret = PAM_IGNORE;
        }
    }

    flock(fd, LOCK_UN);
    close(fd);
    return ret;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_IGNORE;
}
