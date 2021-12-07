FROM clux/muslrust:1.56.1 as build-env
WORKDIR /app
COPY . .
RUN cargo build --release

FROM gcr.io/distroless/static:nonroot
COPY --from=build-env --chown=nonroot:nonroot /app/target/x86_64-unknown-linux-musl/release/auth1 /
EXPOSE 8000
CMD ["/auth1"]
