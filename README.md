# proxy-cpp

A lightweight, multithreaded HTTP/HTTPS forward proxy written in modern C++20 using Boost.Beast and Boost.Asio. Supports HTTP forwarding and HTTPS CONNECT tunneling with bcrypt-hashed password authentication.

***

## Features

- HTTP forward proxy with absolute-URI and `Host`-header request support
- HTTPS CONNECT tunneling (end-to-end TLS — the proxy never sees plaintext HTTPS traffic)
- Basic proxy authentication (`Proxy-Authorization`) with bcrypt-hashed passwords (`$2a$`, `$2b$`, `$2y$`)
- Thread-safe password verification via `crypt_r(3)` with constant-time comparison
- Per-connection socket timeouts (read, write, tunnel idle)
- `Proxy-Authorization` and `Proxy-Connection` headers stripped before upstream forwarding
- Docker multi-stage build targeting Alpine 3.21
- Log rotation and healthcheck via Docker Compose

***

## Project Structure

```
.
├── main.cpp             # Proxy source
├── CMakeLists.txt       # CMake build definition
├── Dockerfile           # Multi-stage Docker build (Alpine 3.21)
├── docker-compose.yml   # Compose with healthcheck + log rotation
├── proxy.conf           # Runtime configuration
├── users.bcrypt         # Bcrypt password database
└── .env                 # Healthcheck credentials (never commit)
```


***

## Configuration

### `proxy.conf`

```ini
listen=0.0.0.0
port=8043
password_file=/etc/proxy-cpp/users.bcrypt
```

| Key | Default | Description |
| :-- | :-- | :-- |
| `listen` | `0.0.0.0` | Bind address |
| `port` | `8043` | Listen port |
| `password_file` | *(required)* | Path to bcrypt password file |

### `users.bcrypt`

One `username:bcrypt_hash` entry per line. Lines starting with `#` are ignored.

```
# /etc/proxy-cpp/users.bcrypt
alice:$2b$12$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
bob:$2b$12$yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy
```

**Generate a hash:**

```bash
# Python
python3 -c "import bcrypt; print(bcrypt.hashpw(b'mypassword', bcrypt.gensalt(12)).decode())"

# htpasswd (apache2-utils)
htpasswd -bnBC 12 user mypassword | cut -d: -f2
```


***

## Building

### Requirements

| Dependency | Version | Package |
| :-- | :-- | :-- |
| GCC/Clang | C++20 | `build-base` |
| CMake | ≥ 3.20 | `cmake` |
| Boost | ≥ 1.74 | `boost-dev` |
| libcrypt | any | part of `build-base` |

### Native build

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
./build/proxy-cpp proxy.conf
```


### Docker

```bash
docker build -t proxy-cpp .
docker run -d \
  -p 8043:8043 \
  -v ./proxy.conf:/etc/proxy-cpp/proxy.conf:ro \
  -v ./users.bcrypt:/etc/proxy-cpp/users.bcrypt:ro \
  proxy-cpp
```


### Docker Compose

Create a `.env` file with healthcheck credentials:

```bash
PROXY_USER=healthcheck
PROXY_PASS=your-healthcheck-password
```

Add the healthcheck user to `users.bcrypt`:

```bash
python3 -c "import bcrypt; print('healthcheck:' + bcrypt.hashpw(b'your-healthcheck-password', bcrypt.gensalt(12)).decode())" >> users.bcrypt
```

Start the stack:

```bash
docker compose up -d --build
docker compose ps         # check health status
docker compose logs -f    # follow logs
```


***

## Testing

```bash
# Should return 407 — proxy is alive, no credentials supplied
curl -v -x http://127.0.0.1:8043 http://httpbin.org/get

# Should return 200 — authenticated HTTP request
curl -v -x http://alice:mypassword@127.0.0.1:8043 http://httpbin.org/get

# Should tunnel TLS correctly — authenticated HTTPS
curl -v -x http://alice:mypassword@127.0.0.1:8043 https://httpbin.org/get

# Verify Proxy-Authorization is stripped before reaching upstream
curl -s -x http://alice:mypassword@127.0.0.1:8043 http://httpbin.org/headers \
  | grep -i proxy   # should return empty
```


***

## Timeouts

| Constant | Default | Description |
| :-- | :-- | :-- |
| `kClientReadTimeout` | 30s | Reading request from client |
| `kClientWriteTimeout` | 30s | Writing response to client |
| `kUpstreamConnectTimeout` | 10s | TCP connect to upstream host |
| `kUpstreamReadTimeout` | 30s | Reading response from upstream |
| `kUpstreamWriteTimeout` | 30s | Writing request to upstream |
| `kTunnelIdleTimeout` | 60s | Idle timeout on CONNECT tunnels |


***

## Security Notes

- Passwords are **never stored or logged in plaintext** — only bcrypt hashes are read at startup
- `crypt_r(3)` is used instead of `crypt(3)` to keep verification **thread-safe** (stack-allocated `crypt_data`)
- Hash comparison uses a **constant-time loop** to prevent timing side-channel attacks
- `Proxy-Authorization` headers are **stripped** from all forwarded requests
- The `.env` file containing healthcheck credentials should **never be committed** to version control — add it to `.gitignore`

