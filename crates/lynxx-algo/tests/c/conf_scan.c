/* Config-like token scan (subset of ngx_conf_read_token character rules) */

#include <stddef.h>
#include <stdint.h>

typedef unsigned char u_char;

size_t
c_ngx_conf_scan_tokens(const u_char *buf, size_t len)
{
    u_char          ch;
    size_t          n;
    unsigned        quoted, s_quoted, d_quoted, sharp, in_token;
    const u_char   *p, *end;

    n = 0;
    quoted = 0;
    s_quoted = 0;
    d_quoted = 0;
    sharp = 0;
    in_token = 0;

    p = buf;
    end = buf + len;

    while (p < end) {
        ch = *p++;

        if (ch == '\n') {
            sharp = 0;
            continue;
        }

        if (sharp) {
            continue;
        }

        if (quoted) {
            quoted = 0;
            continue;
        }

        if (ch == '#') {
            sharp = 1;
            continue;
        }

        if (ch == '\\' && !s_quoted && !d_quoted) {
            quoted = 1;
            continue;
        }

        if (ch == '"' && !s_quoted) {
            d_quoted = !d_quoted;
            in_token = 0;
            continue;
        }

        if (ch == '\'' && !d_quoted) {
            s_quoted = !s_quoted;
            in_token = 0;
            continue;
        }

        if (s_quoted || d_quoted) {
            continue;
        }

        if (ch == ' ' || ch == '\t' || ch == '\r') {
            in_token = 0;
            continue;
        }

        if (ch == ';' || ch == '{' || ch == '}') {
            n++;
            in_token = 0;
            continue;
        }

        if (!in_token) {
            n++;
            in_token = 1;
        }
    }

    return n;
}
