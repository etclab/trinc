ARG GO_VERSION=1.24.2

FROM golang:${GO_VERSION}-alpine as builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build ./cmd/trinctool 

FROM alpine:latest

COPY --from=builder /app/trinctool /usr/local/bin/trinctool
COPY --from=builder /app/testdata /testdata/

CMD ["sleep", "infinity"]