FROM golang:1.22.0-alpine AS build_deps
WORKDIR /workspace
RUN apk add --no-cache git
COPY go.mod .
COPY go.sum .
RUN go mod download

FROM build_deps AS build
COPY . .
RUN CGO_ENABLED=0 go build -o webhook -ldflags '-w -extldflags "-static"' .

FROM alpine:3.18
RUN apk add --no-cache ca-certificates
COPY --from=build /workspace/webhook /usr/local/bin/webhook

ENTRYPOINT ["webhook"]