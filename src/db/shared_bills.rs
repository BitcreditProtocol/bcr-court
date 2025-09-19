use async_trait::async_trait;

use crate::db::PostgresStore;

#[async_trait]
pub trait SharedBillsStore: Send + Sync {}

#[async_trait]
impl SharedBillsStore for PostgresStore {}
