FROM alpine
RUN apk add --no-cache curl grep

WORKDIR /app
COPY ddns-go /app/
ENTRYPOINT ["/app/ddns-go"]
CMD ["-f", "300"]
