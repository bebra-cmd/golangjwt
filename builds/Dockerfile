FROM golang:1.22.5-alpine AS builder 
copy go.mod go.sum ./
run go mod download
copy . ./
RUN go build -o /bin/app ./cmd/main/main.go
FROM alpine:latest
run mkdir logs
run touch /logs/app.log
COPY --from=builder /bin/app /app
CMD ["/app"]