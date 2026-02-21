pub mod cache;
pub mod fakeip;
pub mod resolver;
pub mod server;

pub use fakeip::FakeIpPool;
pub use resolver::Resolver;
pub use server::DnsServer;
