//! Shared test utilities for integration tests.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::time::{Duration, sleep};

use shspectr_web::application::state::AppState;
use shspectr_web::infrastructure::database::{DbPool, create_test_pool};
use shspectr_web::infrastructure::repositories::event::SqlEventRepository;

/// Spin up a test server with an in-memory DB and return `(addr, pool)`.
///
/// The pool is returned so tests can seed data into the database.
pub async fn start_test_server() -> (SocketAddr, DbPool) {
    let pool = create_test_pool().expect("create test pool");
    let repo = Arc::new(SqlEventRepository::new(pool.clone()));
    let state = AppState { repo };

    let app = shspectr_web::application::routes::router().with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");

    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    sleep(Duration::from_millis(50)).await;
    (addr, pool)
}
