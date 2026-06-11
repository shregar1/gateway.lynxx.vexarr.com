//! Timer key comparison — `ngx_rbtree_insert_timer_value` in `src/core/ngx_rbtree.c`

/// `(ngx_rbtree_key_int_t)(node->key - temp->key) < 0` — overflow-safe ms compare.
#[inline(always)]
pub fn ngx_rbtree_timer_less(node_key: u32, temp_key: u32) -> bool {
    (node_key.wrapping_sub(temp_key) as i32) < 0
}
