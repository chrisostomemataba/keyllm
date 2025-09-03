FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /keyllm .

FROM alpine:latest
WORKDIR /app
RUN mkdir /data
COPY --from=builder /keyllm .
COPY web ./web

COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh

EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/app/keyllm"]