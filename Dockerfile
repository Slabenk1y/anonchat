FROM rust:1-slim AS build
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:stable-slim
COPY --from=build /app/target/release/anon-chat /usr/local/bin/anon-chat
ENV CHAT_PROXY_HOPS=1
CMD ["anon-chat"]
