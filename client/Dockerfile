# ---- build stage: static binary, no CGO, stripped ----
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/client ./client

# ---- runtime stage: minimal, unprivileged ----
FROM alpine:3.20
RUN addgroup -S app && adduser -S -G app app
COPY --from=build /out/client /usr/local/bin/client
USER app
ENTRYPOINT ["/usr/local/bin/client"]
