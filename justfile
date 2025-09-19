build:
    cargo build

clean:
    cargo clean

TESTS := ""
test:
    cargo test {{TESTS}} --offline -- --color=always --nocapture

fmt:
    cargo fmt --all -- --check

lint:
    cargo clippy --all-targets --all-features -- -D warnings

watch:
    COURT__LOG_LEVEL=debug RUST_BACKTRACE=1 watchexec -r cargo run

dev:
    COURT__LOG_LEVEL=debug RUST_BACKTRACE=1 cargo run

