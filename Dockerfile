FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /otpkit ./cmd/otpkit

FROM scratch
COPY --from=builder /otpkit /otpkit
EXPOSE 8470
ENTRYPOINT ["/otpkit"]
