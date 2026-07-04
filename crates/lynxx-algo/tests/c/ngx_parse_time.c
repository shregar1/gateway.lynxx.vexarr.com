/* ngx_parse_time extract (ngx_parse.c) */

#include <stddef.h>
#include <stdint.h>
#include <limits.h>

typedef unsigned char u_char;

#define C_NGX_ERROR ((int64_t) -1)
#define C_NGX_MAX_INT LLONG_MAX

int64_t
c_ngx_parse_time(u_char *line, size_t len, unsigned is_sec)
{
    u_char      *p, *last;
    int64_t      value, total, scale;
    int64_t      max, cutoff, cutlim;
    unsigned     valid;
    enum {
        st_start = 0,
        st_year,
        st_month,
        st_week,
        st_day,
        st_hour,
        st_min,
        st_sec,
        st_msec,
        st_last
    } step;

    valid = 0;
    value = 0;
    total = 0;
    cutoff = C_NGX_MAX_INT / 10;
    cutlim = C_NGX_MAX_INT % 10;
    step = is_sec ? st_start : st_month;

    p = line;
    last = p + len;

    while (p < last) {

        if (*p >= '0' && *p <= '9') {
            if (value >= cutoff && (value > cutoff || *p - '0' > cutlim)) {
                return C_NGX_ERROR;
            }

            value = value * 10 + (*p++ - '0');
            valid = 1;
            continue;
        }

        switch (*p++) {

        case 'y':
            if (step > st_start) {
                return C_NGX_ERROR;
            }
            step = st_year;
            max = C_NGX_MAX_INT / (60 * 60 * 24 * 365);
            scale = 60 * 60 * 24 * 365;
            break;

        case 'M':
            if (step >= st_month) {
                return C_NGX_ERROR;
            }
            step = st_month;
            max = C_NGX_MAX_INT / (60 * 60 * 24 * 30);
            scale = 60 * 60 * 24 * 30;
            break;

        case 'w':
            if (step >= st_week) {
                return C_NGX_ERROR;
            }
            step = st_week;
            max = C_NGX_MAX_INT / (60 * 60 * 24 * 7);
            scale = 60 * 60 * 24 * 7;
            break;

        case 'd':
            if (step >= st_day) {
                return C_NGX_ERROR;
            }
            step = st_day;
            max = C_NGX_MAX_INT / (60 * 60 * 24);
            scale = 60 * 60 * 24;
            break;

        case 'h':
            if (step >= st_hour) {
                return C_NGX_ERROR;
            }
            step = st_hour;
            max = C_NGX_MAX_INT / (60 * 60);
            scale = 60 * 60;
            break;

        case 'm':
            if (p < last && *p == 's') {
                if (is_sec || step >= st_msec) {
                    return C_NGX_ERROR;
                }
                p++;
                step = st_msec;
                max = C_NGX_MAX_INT;
                scale = 1;
                break;
            }

            if (step >= st_min) {
                return C_NGX_ERROR;
            }
            step = st_min;
            max = C_NGX_MAX_INT / 60;
            scale = 60;
            break;

        case 's':
            if (step >= st_sec) {
                return C_NGX_ERROR;
            }
            step = st_sec;
            max = C_NGX_MAX_INT;
            scale = 1;
            break;

        case ' ':
            if (step >= st_sec) {
                return C_NGX_ERROR;
            }
            step = st_last;
            max = C_NGX_MAX_INT;
            scale = 1;
            break;

        default:
            return C_NGX_ERROR;
        }

        if (step != st_msec && !is_sec) {
            scale *= 1000;
            max /= 1000;
        }

        if (value > max) {
            return C_NGX_ERROR;
        }

        value *= scale;

        if (total > C_NGX_MAX_INT - value) {
            return C_NGX_ERROR;
        }

        total += value;

        value = 0;

        while (p < last && *p == ' ') {
            p++;
        }
    }

    if (!valid) {
        return C_NGX_ERROR;
    }

    if (!is_sec) {
        if (value > C_NGX_MAX_INT / 1000) {
            return C_NGX_ERROR;
        }

        value *= 1000;
    }

    if (total > C_NGX_MAX_INT - value) {
        return C_NGX_ERROR;
    }

    return total + value;
}
