pub mod postgres;
pub mod redis;

pub trait DbPool {
    fn initialize(params: &str) -> Self;

    fn for_tests() -> Self;
}
