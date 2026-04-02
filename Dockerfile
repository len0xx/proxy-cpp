# =============================================================================
# Build stage — Alpine + musl toolchain
# =============================================================================
FROM alpine:3.21 AS build

# boost-dev pulls boost-system; crypt_r is part of musl-libc on Alpine,
# so no separate libxcrypt/libcrypt package is needed.
RUN apk add --no-cache \
    build-base \
    cmake \
    boost-dev \
    linux-headers \
    ca-certificates

WORKDIR /src

COPY CMakeLists.txt  .
COPY main.cpp  .

# Static-link libstdc++ and libgcc so the runtime stage needs zero
# C++ runtime shared libraries beyond musl libc.
RUN cmake -S . -B build \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_EXE_LINKER_FLAGS="-static-libstdc++ -static-libgcc" \
 && cmake --build build -j"$(nproc)" \
 && strip --strip-all build/proxy-cpp

# =============================================================================
# Runtime stage — minimal Alpine
# =============================================================================
FROM alpine:3.21

# ca-certificates — TLS root CAs for upstream HTTPS connections
# curl            — used by the healthcheck in docker-compose.yml
RUN apk add --no-cache \
    ca-certificates \
    curl

# Unprivileged user
RUN addgroup -S proxy && adduser -S -G proxy proxy

WORKDIR /app

COPY --from=build /src/build/proxy-cpp  /usr/local/bin/proxy-cpp
COPY proxy.conf /etc/proxy-cpp/proxy.conf

# Create config dir with correct ownership for bind-mounted files
RUN chown proxy:proxy /etc/proxy-cpp

USER proxy

EXPOSE 8043

ENTRYPOINT ["/usr/local/bin/proxy-cpp"]
CMD        ["/etc/proxy-cpp/proxy.conf"]

