FROM golang:1.24-bookworm AS base

# Copy GoBGP
COPY . /root/

WORKDIR /root

# Install GoBGP
RUN go install ./...

# Expose BGP and gRPC ports
EXPOSE 179 50051 17900

# Run gobgpd with the config file
CMD ["gobgpd", "-f", "demo.conf", "-l", "debug", "-p"]
# CMD ["sh"]
