use lynxx_algo::{
    ngx_crc32_long, ngx_crc32_long_table, ngx_crc32_short, ngx_crc32_short_nibble,
};

#[test]
fn crc32fast_matches_nginx_tables() {
    for len in [0, 1, 15, 16, 60, 61, 100, 4096] {
        let data: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(31)).collect();
        let nginx_long = ngx_crc32_long(&data);
        let fast_long = crc32fast::hash(&data);
        assert_eq!(nginx_long, fast_long, "long len={len}");
        assert_eq!(ngx_crc32_long_table(&data), fast_long, "table len={len}");

        assert_eq!(ngx_crc32_short(&data), crc32fast::hash(&data), "short len={len}");
        assert_eq!(
            ngx_crc32_short_nibble(&data),
            crc32fast::hash(&data),
            "nibble len={len}"
        );
    }
    for len in 0..=64 {
        let data: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(17)).collect();
        assert_eq!(ngx_crc32_short(&data), ngx_crc32_short_nibble(&data), "len={len}");
    }
}
