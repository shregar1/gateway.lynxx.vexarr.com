/* Minimal radix tree for bench/parity (from ngx_radix_tree.c). */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef unsigned char u_char;

#define C_NGX_RADIX_NO_VALUE ((uintptr_t) -1)
#define C_NGX_OK 0
#define C_NGX_BUSY -2
#define C_NGX_ERROR -1

typedef struct c_radix_node_s {
    struct c_radix_node_s  *right;
    struct c_radix_node_s  *left;
    struct c_radix_node_s  *parent;
    uintptr_t               value;
} c_radix_node_t;

typedef struct {
    c_radix_node_t  *root;
    c_radix_node_t  *free;
    c_radix_node_t  *nodes;
    size_t           n;
    size_t           cap;
} c_radix_tree_t;

static c_radix_node_t c_radix_storage[4096];
static c_radix_tree_t c_geo_tree;
static int            c_geo_tree_ready;

static c_radix_node_t *
c_radix_alloc(c_radix_tree_t *tree)
{
    c_radix_node_t  *p;

    if (tree->free) {
        p = tree->free;
        tree->free = tree->free->right;
        return p;
    }

    if (tree->n >= tree->cap) {
        return NULL;
    }

    p = &tree->nodes[tree->n++];
    return p;
}

static c_radix_tree_t *
c_radix_create(void)
{
    c_radix_tree_t  *tree;
    c_radix_node_t  *root;

    tree = &c_geo_tree;
    memset(tree, 0, sizeof(*tree));
    tree->nodes = c_radix_storage;
    tree->cap = sizeof(c_radix_storage) / sizeof(c_radix_storage[0]);
    tree->n = 0;

    root = c_radix_alloc(tree);
    if (root == NULL) {
        return NULL;
    }

    root->right = NULL;
    root->left = NULL;
    root->parent = NULL;
    root->value = C_NGX_RADIX_NO_VALUE;
    tree->root = root;

    return tree;
}

static int
c_radix32tree_insert(c_radix_tree_t *tree, uint32_t key, uint32_t mask,
    uintptr_t value);

static void
c_radix_preallocate(c_radix_tree_t *tree)
{
    uint32_t  mask, inc, key;
    int       i;

    mask = 0;
    inc = 0x80000000;

    for (i = 0; i < 7; i++) {
        mask >>= 1;
        mask |= 0x80000000;

        key = 0;
        do {
            (void) c_radix32tree_insert(tree, key, mask, C_NGX_RADIX_NO_VALUE);
            key += inc;
        } while (key);
        inc >>= 1;
    }
}

static int
c_radix32tree_insert(c_radix_tree_t *tree, uint32_t key, uint32_t mask,
    uintptr_t value)
{
    uint32_t           bit;
    c_radix_node_t    *node, *next;

    bit = 0x80000000;

    node = tree->root;
    next = tree->root;

    while (bit & mask) {
        if (key & bit) {
            next = node->right;
        } else {
            next = node->left;
        }

        if (next == NULL) {
            break;
        }

        bit >>= 1;
        node = next;
    }

    if (next) {
        if (node->value != C_NGX_RADIX_NO_VALUE) {
            return C_NGX_BUSY;
        }

        node->value = value;
        return C_NGX_OK;
    }

    while (bit & mask) {
        next = c_radix_alloc(tree);
        if (next == NULL) {
            return C_NGX_ERROR;
        }

        next->right = NULL;
        next->left = NULL;
        next->parent = node;
        next->value = C_NGX_RADIX_NO_VALUE;

        if (key & bit) {
            node->right = next;
        } else {
            node->left = next;
        }

        bit >>= 1;
        node = next;
    }

    node->value = value;

    return C_NGX_OK;
}

uintptr_t
c_ngx_radix32tree_find(c_radix_tree_t *tree, uint32_t key)
{
    uint32_t           bit;
    uintptr_t          value;
    c_radix_node_t    *node;

    bit = 0x80000000;
    value = C_NGX_RADIX_NO_VALUE;
    node = tree->root;

    while (node) {
        if (node->value != C_NGX_RADIX_NO_VALUE) {
            value = node->value;
        }

        if (key & bit) {
            node = node->right;
        } else {
            node = node->left;
        }

        bit >>= 1;
    }

    return value;
}

void
c_radix_bench_tree_init(void)
{
    c_radix_tree_t  *tree;

    if (c_geo_tree_ready) {
        return;
    }

    tree = c_radix_create();
    if (tree == NULL) {
        return;
    }

    c_radix_preallocate(tree);

    (void) c_radix32tree_insert(tree, 0x0b000000, 0xff000000, 1);
    (void) c_radix32tree_insert(tree, 0x7f000000, 0xff000000, 2);
    (void) c_radix32tree_insert(tree, 0xc0a80100, 0xffffff00, 3);
    (void) c_radix32tree_insert(tree, 0xcb007100, 0xfffffff0, 4);

    c_geo_tree_ready = 1;
}

uintptr_t
c_radix_bench_find(uint32_t key)
{
    c_radix_bench_tree_init();
    return c_ngx_radix32tree_find(&c_geo_tree, key);
}
