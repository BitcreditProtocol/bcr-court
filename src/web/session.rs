use async_trait::async_trait;
use std::{collections::HashMap, sync::Arc};

use tokio::sync::Mutex;
use tower_sessions::{
    ExpiredDeletion, SessionStore,
    cookie::time::OffsetDateTime,
    session::{Id, Record},
    session_store,
};

#[derive(Default, Clone, Debug)]
pub struct InMemSessionStore(Arc<Mutex<HashMap<Id, Record>>>);

#[async_trait()]
impl SessionStore for InMemSessionStore {
    async fn create(&self, record: &mut Record) -> session_store::Result<()> {
        let mut store_guard = self.0.lock().await;
        while store_guard.contains_key(&record.id) {
            record.id = Id::default();
        }
        store_guard.insert(record.id, record.clone());
        Ok(())
    }

    async fn save(&self, record: &Record) -> session_store::Result<()> {
        self.0.lock().await.insert(record.id, record.clone());
        Ok(())
    }

    async fn load(&self, session_id: &Id) -> session_store::Result<Option<Record>> {
        Ok(self
            .0
            .lock()
            .await
            .get(session_id)
            .filter(|Record { expiry_date, .. }| expiry_date > &OffsetDateTime::now_utc())
            .cloned())
    }

    async fn delete(&self, session_id: &Id) -> session_store::Result<()> {
        self.0.lock().await.remove(session_id);
        Ok(())
    }
}

#[async_trait()]
impl ExpiredDeletion for InMemSessionStore {
    async fn delete_expired(&self) -> session_store::Result<()> {
        tracing::debug!("deleting expired sessions");
        self.0
            .lock()
            .await
            .retain(|_key, &mut Record { expiry_date, .. }| {
                expiry_date >= OffsetDateTime::now_utc()
            });
        Ok(())
    }
}
