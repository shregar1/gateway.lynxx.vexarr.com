#include <stdio.h>
#include <stddef.h>

typedef unsigned char u_char;

size_t c_ngx_http_huff_encode(u_char *src, size_t len, u_char *dst);

int
main(void)
{
    u_char  src[] = "www.example.com";
    u_char  dst[64];
    size_t  i, n;

    n = c_ngx_http_huff_encode(src, sizeof(src) - 1, dst);
    for (i = 0; i < n; i++) {
        printf("0x%02x, ", dst[i]);
    }
    return 0;
}
