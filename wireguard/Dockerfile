FROM alpine:3.19

RUN apk add --no-cache wireguard-tools iproute2

COPY entrypoint.sh /entrypoint.sh
# Strip CRLF (Windows line endings) so exec does not fail with "no such file or directory"
RUN sed -i 's/\r$//' /entrypoint.sh && chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
