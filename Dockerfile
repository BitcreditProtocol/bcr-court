##############################
## Build bcr-court
##############################
FROM rust:latest AS rust-builder

WORKDIR /bcr-court
RUN update-ca-certificates
COPY . .

RUN cargo build --release

##############################
## Create image for docker compose
##############################
FROM ubuntu:22.04

RUN apt-get update && \
  apt-get install -y ca-certificates libpq5 && \
  apt-get clean

WORKDIR /bcr-court

# Copy binary release
COPY --from=rust-builder /bcr-court/target/release/bcr-court ./bcr-court
COPY --from=rust-builder /bcr-court/static/ ./static/
COPY --from=rust-builder /bcr-court/config/ ./config/

RUN chmod +x /bcr-court/bcr-court

# Expose server port
EXPOSE 8000

CMD ["/bcr-court/bcr-court"]
