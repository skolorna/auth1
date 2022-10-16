FROM clux/muslrust:1.64.0 as build
WORKDIR /app
COPY . .
RUN cargo build --release

FROM gcr.io/distroless/static-debian11
COPY --from=build /app/target/x86_64-unknown-linux-musl/release/auth1 /
EXPOSE 8000
CMD ["/auth1"]
