use ipnet::Ipv4Net;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

pub struct FakeIpPool {
    inner: Mutex<FakeIpPoolInner>,
    network: Ipv4Net,
}

struct FakeIpPoolInner {
    offset: u32,
    host_to_ip: HashMap<String, Ipv4Addr>,
    ip_to_host: HashMap<Ipv4Addr, String>,
    min: u32,
    max: u32,
}

impl FakeIpPool {
    /// Create a new FakeIP pool from a CIDR like "198.18.0.0/15"
    pub fn new(cidr: &str) -> Result<Self, String> {
        let network: Ipv4Net = cidr.parse().map_err(|e| format!("invalid CIDR: {}", e))?;
        let min_ip = u32::from(network.network()) + 2; // skip network addr and gateway
        let max_ip = u32::from(network.broadcast()) - 1; // skip broadcast
        if min_ip >= max_ip {
            return Err("CIDR range too small".into());
        }
        Ok(Self {
            inner: Mutex::new(FakeIpPoolInner {
                offset: 0,
                host_to_ip: HashMap::new(),
                ip_to_host: HashMap::new(),
                min: min_ip,
                max: max_ip,
            }),
            network,
        })
    }

    /// Get or allocate a fake IP for the given host
    pub fn lookup_host(&self, host: &str) -> IpAddr {
        let mut inner = self.inner.lock();
        if let Some(&ip) = inner.host_to_ip.get(host) {
            return IpAddr::V4(ip);
        }
        let ip = Self::allocate_ip(&mut inner);
        // If this IP was previously allocated to a different host, remove the old mapping
        if let Some(old_host) = inner.ip_to_host.remove(&ip) {
            inner.host_to_ip.remove(&old_host);
        }
        inner.host_to_ip.insert(host.to_string(), ip);
        inner.ip_to_host.insert(ip, host.to_string());
        IpAddr::V4(ip)
    }

    /// Look up the host for a given fake IP
    pub fn lookup_ip(&self, ip: IpAddr) -> Option<String> {
        let ipv4 = match ip {
            IpAddr::V4(v4) => v4,
            _ => return None,
        };
        let inner = self.inner.lock();
        inner.ip_to_host.get(&ipv4).cloned()
    }

    /// Check if an IP is within the fake IP range
    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.network.contains(&v4),
            _ => false,
        }
    }

    fn allocate_ip(inner: &mut FakeIpPoolInner) -> Ipv4Addr {
        let range = inner.max - inner.min;
        let ip_u32 = inner.min + (inner.offset % range);
        inner.offset = inner.offset.wrapping_add(1);
        Ipv4Addr::from(ip_u32)
    }

    pub fn network(&self) -> &Ipv4Net {
        &self.network
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fakeip_allocation() {
        let pool = FakeIpPool::new("198.18.0.0/15").unwrap();
        let ip1 = pool.lookup_host("example.com");
        let ip2 = pool.lookup_host("google.com");
        assert_ne!(ip1, ip2);

        // Same host returns same IP
        let ip1_again = pool.lookup_host("example.com");
        assert_eq!(ip1, ip1_again);
    }

    #[test]
    fn test_fakeip_reverse_lookup() {
        let pool = FakeIpPool::new("198.18.0.0/15").unwrap();
        let ip = pool.lookup_host("example.com");
        assert_eq!(pool.lookup_ip(ip), Some("example.com".to_string()));
    }

    #[test]
    fn test_fakeip_contains() {
        let pool = FakeIpPool::new("198.18.0.0/15").unwrap();
        assert!(pool.contains(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 5))));
        assert!(!pool.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }
}
