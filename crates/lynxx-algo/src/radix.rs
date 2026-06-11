//! `ngx_radix32tree_find()` — `src/core/ngx_radix_tree.c` (geo / map lookups).

pub const NGX_RADIX_NO_VALUE: usize = usize::MAX;

const NULL: u32 = u32::MAX;
const NO_VALUE: u32 = u32::MAX;

/// Radix tree node (`ngx_radix_node_t`): same field order as NGINX (`right`, `left`).
#[repr(C)]
pub struct RadixNode {
    pub right: u32,
    pub left: u32,
    pub value: u32,
}

/// IPv4 radix tree (stable arena).
pub struct RadixTree32 {
    nodes: Vec<RadixNode>,
    free: u32,
}

#[inline]
fn to_store(v: usize) -> u32 {
    if v == NGX_RADIX_NO_VALUE {
        NO_VALUE
    } else {
        v as u32
    }
}

impl RadixTree32 {
    pub fn new() -> Self {
        let mut t = Self {
            nodes: Vec::with_capacity(512),
            free: NULL,
        };
        t.alloc();
        t
    }

    fn alloc(&mut self) -> u32 {
        if self.free != NULL {
            let idx = self.free;
            self.free = self.nodes[idx as usize].right;
            let n = &mut self.nodes[idx as usize];
            n.right = NULL;
            n.left = NULL;
            n.value = NO_VALUE;
            return idx;
        }
        let idx = self.nodes.len() as u32;
        self.nodes.push(RadixNode {
            right: NULL,
            left: NULL,
            value: NO_VALUE,
        });
        idx
    }

    /// NGINX `ngx_radix_tree_create(pool, -1)` preallocation.
    pub fn preallocate(&mut self) {
        let mut mask = 0u32;
        let mut inc = 0x8000_0000u32;
        for _ in 0..7 {
            mask >>= 1;
            mask |= 0x8000_0000;
            let mut key = 0u32;
            loop {
                let _ = self.insert(key, mask, NGX_RADIX_NO_VALUE);
                key = key.wrapping_add(inc);
                if key == 0 {
                    break;
                }
            }
            inc >>= 1;
        }
    }

    /// `ngx_radix32tree_insert` — same semantics as NGINX.
    pub fn insert(&mut self, key: u32, mask: u32, value: usize) -> i32 {
        let store = to_store(value);
        let mut bit = 0x8000_0000u32;
        let mut node = 0u32;
        let mut next = 0u32;

        while bit & mask != 0 {
            let n = &self.nodes[node as usize];
            next = if (key & bit) != 0 { n.right } else { n.left };
            if next == NULL {
                break;
            }
            bit >>= 1;
            node = next;
        }

        if next != NULL {
            if self.nodes[node as usize].value != NO_VALUE {
                return -2;
            }
            self.nodes[node as usize].value = store;
            return 0;
        }

        while bit & mask != 0 {
            next = self.alloc();
            let slot = &mut self.nodes[node as usize];
            if (key & bit) != 0 {
                slot.right = next;
            } else {
                slot.left = next;
            }
            bit >>= 1;
            node = next;
        }

        self.nodes[node as usize].value = store;
        0
    }

    /// Longest-prefix match (`ngx_radix32tree_find`).
    #[inline(always)]
    pub fn find(&self, key: u32) -> usize {
        let nodes = self.nodes.as_slice();
        let mut value = NGX_RADIX_NO_VALUE;
        let mut node = 0u32;
        macro_rules! step {
            ($bit:expr) => {
                if node != NULL {
                    let n = unsafe { nodes.get_unchecked(node as usize) };
                    let nv = n.value;
                    if nv != NO_VALUE {
                        value = nv as usize;
                    }
                    node = if (key & $bit) != 0 {
                        n.right
                    } else {
                        n.left
                    };
                }
            };
        }
        step!(0x8000_0000);
        step!(0x4000_0000);
        step!(0x2000_0000);
        step!(0x1000_0000);
        step!(0x0800_0000);
        step!(0x0400_0000);
        step!(0x0200_0000);
        step!(0x0100_0000);
        step!(0x0080_0000);
        step!(0x0040_0000);
        step!(0x0020_0000);
        step!(0x0010_0000);
        step!(0x0008_0000);
        step!(0x0004_0000);
        step!(0x0002_0000);
        step!(0x0001_0000);
        step!(0x8000);
        step!(0x4000);
        step!(0x2000);
        step!(0x1000);
        step!(0x0800);
        step!(0x0400);
        step!(0x0200);
        step!(0x0100);
        step!(0x0080);
        step!(0x0040);
        step!(0x0020);
        step!(0x0010);
        step!(0x0008);
        step!(0x0004);
        step!(0x0002);
        step!(0x0001);
        value
    }
}
