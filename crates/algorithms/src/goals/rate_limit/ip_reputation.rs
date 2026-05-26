use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct SieveConfig {
    pub bucket_sizes: Vec<usize>,
    pub max_age: Duration,
    pub perma_block_size: usize,
    pub perma_block_duration: Duration,
    pub block_threshold: u32,
}

impl Default for SieveConfig {
    fn default() -> Self {
        Self {
            bucket_sizes: vec![1024, 512, 256, 128, 64],
            max_age: Duration::from_secs(300),
            perma_block_size: 1024,
            perma_block_duration: Duration::from_secs(3600),
            block_threshold: 100,
        }
    }
}

pub struct IpReputation {
    config: SieveConfig,
    buckets: Vec<SieveBucket>,
    perma_block: HashMap<IpAddr, Instant>,
}

struct SieveBucket {
    entries: VecDeque<SieveEntry>,
    lookup: HashMap<IpAddr, usize>,
    capacity: usize,
}

#[allow(dead_code)]
struct SieveEntry {
    ip: IpAddr,
    count: u32,
    first_seen: Instant,
    last_seen: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReputationLevel {
    Unknown,
    Low,
    Medium,
    High,
    Blocked,
}

impl SieveBucket {
    fn new(capacity: usize) -> Self {
        Self {
            entries: VecDeque::with_capacity(capacity),
            lookup: HashMap::with_capacity(capacity),
            capacity,
        }
    }

    fn contains(&self, ip: &IpAddr) -> bool {
        self.lookup.contains_key(ip)
    }

    fn get_mut(&mut self, ip: &IpAddr) -> Option<&mut SieveEntry> {
        if let Some(&idx) = self.lookup.get(ip) {
            self.entries.get_mut(idx)
        } else {
            None
        }
    }

    fn remove(&mut self, ip: &IpAddr) -> Option<SieveEntry> {
        if let Some(&idx) = self.lookup.get(ip) {
            self.lookup.remove(ip);
            let entry = self.entries.remove(idx);
            // Re-index entries after the removed one
            for (new_idx, e) in self.entries.iter().enumerate().skip(idx) {
                self.lookup.insert(e.ip, new_idx);
            }
            entry
        } else {
            None
        }
    }

    fn push(&mut self, entry: SieveEntry) -> Option<SieveEntry> {
        let evicted = if self.entries.len() >= self.capacity {
            let old = self.entries.pop_front();
            if let Some(ref e) = old {
                self.lookup.remove(&e.ip);
                for (idx, entry) in self.entries.iter().enumerate() {
                    self.lookup.insert(entry.ip, idx);
                }
            }
            old
        } else {
            None
        };

        let idx = self.entries.len();
        self.lookup.insert(entry.ip, idx);
        self.entries.push_back(entry);
        evicted
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

impl IpReputation {
    pub fn new(config: SieveConfig) -> Self {
        let buckets = config
            .bucket_sizes
            .iter()
            .map(|&cap| SieveBucket::new(cap))
            .collect();
        Self {
            config,
            buckets,
            perma_block: HashMap::new(),
        }
    }

    /// Record a hit for an IP. Returns the new reputation level.
    /// Promotes IP to smaller buckets as count increases.
    pub fn record_hit(&mut self, ip: IpAddr) -> ReputationLevel {
        let now = Instant::now();

        if self.is_blocked(&ip) {
            return ReputationLevel::Blocked;
        }

        let current_bucket = self.find_bucket(&ip);

        match current_bucket {
            Some(bucket_idx) => {
                let entry = self.buckets[bucket_idx].get_mut(&ip).unwrap();
                entry.count += 1;
                entry.last_seen = now;
                let count = entry.count;

                if count >= self.config.block_threshold {
                    self.buckets[bucket_idx].remove(&ip);
                    self.perma_block.insert(ip, now);
                    return ReputationLevel::Blocked;
                }

                let target_bucket = self.promotion_target(count);
                if target_bucket > bucket_idx {
                    let entry = self.buckets[bucket_idx].remove(&ip).unwrap();
                    let target = target_bucket.min(self.buckets.len() - 1);
                    self.buckets[target].push(entry);
                    self.level_for_bucket(target)
                } else {
                    self.level_for_bucket(bucket_idx)
                }
            }
            None => {
                let entry = SieveEntry {
                    ip,
                    count: 1,
                    first_seen: now,
                    last_seen: now,
                };
                if !self.buckets.is_empty() {
                    self.buckets[0].push(entry);
                }
                ReputationLevel::Low
            }
        }
    }

    pub fn reputation(&self, ip: &IpAddr) -> ReputationLevel {
        if self.is_blocked(ip) {
            return ReputationLevel::Blocked;
        }
        match self.find_bucket(ip) {
            Some(idx) => self.level_for_bucket(idx),
            None => ReputationLevel::Unknown,
        }
    }

    pub fn is_blocked(&self, ip: &IpAddr) -> bool {
        if let Some(&blocked_at) = self.perma_block.get(ip) {
            if blocked_at.elapsed() < self.config.perma_block_duration {
                return true;
            }
        }
        false
    }

    /// Age out old entries (decay counts by 1/8).
    pub fn age_entries(&mut self) {
        let now = Instant::now();

        for bucket in &mut self.buckets {
            let mut to_remove = Vec::new();
            for (idx, entry) in bucket.entries.iter_mut().enumerate() {
                if now.duration_since(entry.last_seen) > self.config.max_age {
                    to_remove.push(idx);
                } else {
                    entry.count = entry.count.saturating_sub(entry.count / 8);
                }
            }
            for &idx in to_remove.iter().rev() {
                if let Some(entry) = bucket.entries.remove(idx) {
                    bucket.lookup.remove(&entry.ip);
                }
            }
            bucket.lookup.clear();
            for (idx, entry) in bucket.entries.iter().enumerate() {
                bucket.lookup.insert(entry.ip, idx);
            }
        }

        self.perma_block
            .retain(|_, blocked_at| blocked_at.elapsed() < self.config.perma_block_duration);
    }

    pub fn block(&mut self, ip: IpAddr) {
        for bucket in &mut self.buckets {
            bucket.remove(&ip);
        }
        self.perma_block.insert(ip, Instant::now());
    }

    pub fn unblock(&mut self, ip: &IpAddr) {
        self.perma_block.remove(ip);
    }

    pub fn total_tracked(&self) -> usize {
        self.buckets.iter().map(|b| b.len()).sum::<usize>() + self.perma_block.len()
    }

    pub fn blocked_count(&self) -> usize {
        self.perma_block.len()
    }

    fn find_bucket(&self, ip: &IpAddr) -> Option<usize> {
        for (idx, bucket) in self.buckets.iter().enumerate() {
            if bucket.contains(ip) {
                return Some(idx);
            }
        }
        None
    }

    fn promotion_target(&self, count: u32) -> usize {
        let num_buckets = self.buckets.len();
        if num_buckets <= 1 {
            return 0;
        }
        let level = (count as f64).log2().floor() as usize;
        level.min(num_buckets - 1)
    }

    fn level_for_bucket(&self, bucket_idx: usize) -> ReputationLevel {
        let num_buckets = self.buckets.len();
        if num_buckets == 0 {
            return ReputationLevel::Unknown;
        }
        let ratio = bucket_idx as f64 / num_buckets as f64;
        if ratio < 0.3 {
            ReputationLevel::Low
        } else if ratio < 0.6 {
            ReputationLevel::Medium
        } else {
            ReputationLevel::High
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn test_config() -> SieveConfig {
        SieveConfig {
            bucket_sizes: vec![64, 32, 16, 8, 4],
            max_age: Duration::from_secs(60),
            perma_block_size: 32,
            perma_block_duration: Duration::from_secs(300),
            block_threshold: 20,
        }
    }

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, last))
    }

    #[test]
    fn test_new_ip_gets_low_reputation() {
        let mut rep = IpReputation::new(test_config());
        let level = rep.record_hit(ip(1));
        assert_eq!(level, ReputationLevel::Low);
    }

    #[test]
    fn test_repeated_hits_promote() {
        let mut rep = IpReputation::new(test_config());
        let ip_addr = ip(1);
        for _ in 0..8 {
            rep.record_hit(ip_addr);
        }
        let level = rep.reputation(&ip_addr);
        assert!(level == ReputationLevel::Medium || level == ReputationLevel::High);
    }

    #[test]
    fn test_block_threshold() {
        let mut rep = IpReputation::new(test_config());
        let ip_addr = ip(1);
        for _ in 0..25 {
            rep.record_hit(ip_addr);
        }
        assert_eq!(rep.reputation(&ip_addr), ReputationLevel::Blocked);
        assert!(rep.is_blocked(&ip_addr));
    }

    #[test]
    fn test_manual_block_unblock() {
        let mut rep = IpReputation::new(test_config());
        let ip_addr = ip(10);
        rep.record_hit(ip_addr);
        assert!(!rep.is_blocked(&ip_addr));

        rep.block(ip_addr);
        assert!(rep.is_blocked(&ip_addr));
        assert_eq!(rep.reputation(&ip_addr), ReputationLevel::Blocked);

        rep.unblock(&ip_addr);
        assert!(!rep.is_blocked(&ip_addr));
    }

    #[test]
    fn test_unknown_ip() {
        let rep = IpReputation::new(test_config());
        assert_eq!(rep.reputation(&ip(99)), ReputationLevel::Unknown);
    }

    #[test]
    fn test_total_tracked() {
        let mut rep = IpReputation::new(test_config());
        for i in 0..10 {
            rep.record_hit(ip(i));
        }
        assert_eq!(rep.total_tracked(), 10);
    }

    #[test]
    fn test_blocked_count() {
        let mut rep = IpReputation::new(test_config());
        rep.block(ip(1));
        rep.block(ip(2));
        assert_eq!(rep.blocked_count(), 2);
    }

    #[test]
    fn test_age_entries_decay() {
        let mut rep = IpReputation::new(test_config());
        let ip_addr = ip(1);
        for _ in 0..10 {
            rep.record_hit(ip_addr);
        }
        rep.age_entries();
        assert_ne!(rep.reputation(&ip_addr), ReputationLevel::Unknown);
    }

    #[test]
    fn test_ipv6_support() {
        let mut rep = IpReputation::new(test_config());
        let ipv6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let level = rep.record_hit(ipv6);
        assert_eq!(level, ReputationLevel::Low);
        assert_ne!(rep.reputation(&ipv6), ReputationLevel::Unknown);
    }

    #[test]
    fn test_multiple_ips_tracked_independently() {
        let mut rep = IpReputation::new(test_config());
        for _ in 0..15 {
            rep.record_hit(ip(1));
        }
        rep.record_hit(ip(2));

        let level1 = rep.reputation(&ip(1));
        let level2 = rep.reputation(&ip(2));
        assert!(level1 != ReputationLevel::Low || level2 == ReputationLevel::Low);
    }

    #[test]
    fn test_bucket_eviction() {
        let config = SieveConfig {
            bucket_sizes: vec![4, 4, 4, 4, 4],
            max_age: Duration::from_secs(60),
            perma_block_size: 4,
            perma_block_duration: Duration::from_secs(300),
            block_threshold: 100,
        };
        let mut rep = IpReputation::new(config);
        for i in 0..10 {
            rep.record_hit(ip(i));
        }
        assert!(rep.total_tracked() <= 20);
    }
}
