FROM golang:1.11.5 as builder
RUN mkdir /build
COPY . /build
WORKDIR /build
RUN go get github.com/gorilla/mux
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o oresources .

FROM golang:alpine
RUN mkdir /app
COPY --from=builder /build/oresources /app
WORKDIR /app
RUN addgroup -S resourcesuser && adduser -S resourcesuser -G resourcesuser
RUN chown -R resourcesuser:resourcesuser /app
USER resourcesuser
EXPOSE 8080
ENTRYPOINT ["/app/oresources"]
