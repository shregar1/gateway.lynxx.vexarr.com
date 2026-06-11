//! `ngx_sort` — `src/core/ngx_string.c`

/// NGINX stable insertion sort (parity / tiny n).
pub fn ngx_sort_legacy<T: Clone>(base: &mut [T], cmp: impl Fn(&T, &T) -> i32) {
    if base.len() < 2 {
        return;
    }
    for i in 1..base.len() {
        let tmp = base[i].clone();
        let mut j = i;
        while j > 0 && cmp(&base[j - 1], &tmp) > 0 {
            base[j] = base[j - 1].clone();
            j -= 1;
        }
        base[j] = tmp;
    }
}

/// Production sort: insertion for n&lt;32; unstable quicksort for larger n (faster than NGINX insertion).
#[inline]
pub fn ngx_sort<T, F>(base: &mut [T], cmp: F)
where
    T: Clone,
    F: Fn(&T, &T) -> i32,
{
    if base.len() < 32 {
        ngx_sort_legacy(base, &cmp);
        return;
    }
    base.sort_unstable_by(|a, b| cmp(a, b).cmp(&0));
}
