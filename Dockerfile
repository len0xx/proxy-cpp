FROM ubuntu:24.04 AS build

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    libboost-system-dev \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY CMakeLists.txt .
COPY main.cpp .
COPY proxy.conf .

RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
 && cmake --build build -j"$(nproc)"

FROM ubuntu:24.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    libboost-system-dev \
    curl \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=build /src/build/proxy-cpp /usr/local/bin/proxy-cpp
COPY --from=build /src/proxy.conf /etc/proxy-cpp/proxy.conf

EXPOSE 3128

ENTRYPOINT ["/usr/local/bin/proxy-cpp"]
CMD ["/etc/proxy-cpp/proxy.conf"]

