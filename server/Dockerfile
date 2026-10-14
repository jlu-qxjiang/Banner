# ---- build stage: static binary, no CGO, stripped ----
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/server ./server

# ---- runtime stage: minimal, unprivileged ----
FROM alpine:3.20
RUN addgroup -S app && adduser -S -G app app
COPY --from=build /out/server /usr/local/bin/server
USER app
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/health || exit 1
ENTRYPOINT ["/usr/local/bin/server"]
