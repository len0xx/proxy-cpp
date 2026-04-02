#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/algorithm/string/predicate.hpp>

#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cctype>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <optional>
#include <poll.h>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <utility>

#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <crypt.h>

namespace asio  = boost::asio;
namespace beast = boost::beast;
namespace http  = beast::http;
using tcp = asio::ip::tcp;

using namespace std::chrono_literals;

struct Config {
    std::string listen = "0.0.0.0";
    std::uint16_t port = 3128;
    std::string password_file;
    std::unordered_map<std::string, std::string> users;
};

struct UpstreamTarget {
    std::string host;
    std::string port;
    std::string target;
};

static constexpr auto kClientReadTimeout      = 30s;
static constexpr auto kClientWriteTimeout     = 30s;
static constexpr auto kUpstreamConnectTimeout = 10s;
static constexpr auto kUpstreamReadTimeout    = 30s;
static constexpr auto kUpstreamWriteTimeout   = 30s;
static constexpr auto kTunnelIdleTimeout      = 60s;

static std::string trim(std::string s) {
    auto not_space = [](unsigned char c) { return !std::isspace(c); };

    while (!s.empty() && !not_space(static_cast<unsigned char>(s.front()))) {
        s.erase(s.begin());
    }
    while (!s.empty() && !not_space(static_cast<unsigned char>(s.back()))) {
        s.pop_back();
    }
    return s;
}

static std::string sv_to_string(beast::string_view sv) {
    return std::string(sv.data(), sv.size());
}

static bool iequals_sv(beast::string_view a, std::string_view b) {
    return boost::iequals(sv_to_string(a), std::string(b));
}

static std::string endpoint_to_string(const tcp::endpoint& ep) {
    return ep.address().to_string() + ":" + std::to_string(ep.port());
}

[[noreturn]] static void throw_errno(const char* what) {
    throw std::system_error(errno, std::generic_category(), what);
}

static timeval to_timeval(std::chrono::milliseconds d) {
    timeval tv{};
    const auto secs  = std::chrono::duration_cast<std::chrono::seconds>(d);
    const auto usecs = std::chrono::duration_cast<std::chrono::microseconds>(d - secs);
    tv.tv_sec = static_cast<decltype(tv.tv_sec)>(secs.count());
    tv.tv_usec = static_cast<decltype(tv.tv_usec)>(usecs.count());
    return tv;
}

static void set_fd_nonblocking(int fd, bool enabled) {
    int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        throw_errno("fcntl(F_GETFL)");
    }

    int next = enabled ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
    if (::fcntl(fd, F_SETFL, next) < 0) {
        throw_errno("fcntl(F_SETFL)");
    }
}

static void set_fd_timeouts(
    int fd,
    std::chrono::milliseconds recv_timeout,
    std::chrono::milliseconds send_timeout
) {
    timeval rcv = to_timeval(recv_timeout);
    if (::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &rcv, sizeof(rcv)) < 0) {
        throw_errno("setsockopt(SO_RCVTIMEO)");
    }

    timeval snd = to_timeval(send_timeout);
    if (::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &snd, sizeof(snd)) < 0) {
        throw_errno("setsockopt(SO_SNDTIMEO)");
    }
}

static void apply_socket_timeouts(
    tcp::socket& sock,
    std::chrono::milliseconds recv_timeout,
    std::chrono::milliseconds send_timeout
) {
    set_fd_timeouts(sock.native_handle(), recv_timeout, send_timeout);
}

static void close_fd(int fd) {
    if (fd >= 0) {
        ::close(fd);
    }
}

static tcp::socket connect_with_timeout_posix(
    asio::io_context& ioc,
    const tcp::resolver::results_type& endpoints,
    std::chrono::milliseconds timeout
) {
    int last_errno = ETIMEDOUT;

    for (auto const& entry : endpoints) {
        const auto ep = entry.endpoint();
        int fd = ::socket(ep.protocol().family(), SOCK_STREAM, 0);
        if (fd < 0) {
            last_errno = errno;
            continue;
        }

        try {
            set_fd_nonblocking(fd, true);

            int rc = ::connect(
                fd,
                reinterpret_cast<const sockaddr*>(ep.data()),
                ep.size()
            );

            if (rc < 0) {
                if (errno != EINPROGRESS) {
                    last_errno = errno;
                    close_fd(fd);
                    continue;
                }

                pollfd pfd{};
                pfd.fd = fd;
                pfd.events = POLLOUT;

                int timeout_ms = static_cast<int>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(timeout).count()
                );

                do {
                    rc = ::poll(&pfd, 1, timeout_ms);
                } while (rc < 0 && errno == EINTR);

                if (rc == 0) {
                    last_errno = ETIMEDOUT;
                    close_fd(fd);
                    continue;
                }

                if (rc < 0) {
                    last_errno = errno;
                    close_fd(fd);
                    continue;
                }

                int so_error = 0;
                socklen_t len = sizeof(so_error);
                if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0) {
                    last_errno = errno;
                    close_fd(fd);
                    continue;
                }

                if (so_error != 0) {
                    last_errno = so_error;
                    close_fd(fd);
                    continue;
                }
            }

            set_fd_nonblocking(fd, false);

            tcp::socket sock(ioc);
            boost::system::error_code ec;
            sock.assign(ep.protocol(), fd, ec);
            if (ec) {
                close_fd(fd);
                throw boost::system::system_error(ec);
            }

            return sock;
        } catch (...) {
            close_fd(fd);
            throw;
        }
    }

    throw std::system_error(last_errno, std::generic_category(), "connect");
}

static bool is_bcrypt_hash(std::string_view hash) {
    return boost::starts_with(hash, "$2a$") ||
           boost::starts_with(hash, "$2b$") ||
           boost::starts_with(hash, "$2y$");
}

static std::unordered_map<std::string, std::string>
load_password_file(const std::string& path) {
    std::ifstream in(path);
    if (!in) {
        throw std::runtime_error("cannot open password file: " + path);
    }

    std::unordered_map<std::string, std::string> users;
    std::string line;
    std::size_t line_no = 0;

    while (std::getline(in, line)) {
        ++line_no;
        line = trim(line);

        if (line.empty() || line[0] == '#') {
            continue;
        }

        auto colon = line.find(':');
        if (colon == std::string::npos) {
            throw std::runtime_error(
                "invalid password file entry at line " + std::to_string(line_no)
            );
        }

        std::string user = trim(line.substr(0, colon));
        std::string hash = trim(line.substr(colon + 1));

        if (user.empty() || hash.empty()) {
            throw std::runtime_error(
                "empty username or hash at line " + std::to_string(line_no)
            );
        }

        if (!is_bcrypt_hash(hash)) {
            throw std::runtime_error(
                "password for user '" + user + "' is not a bcrypt hash"
            );
        }

        auto [it, inserted] = users.emplace(std::move(user), std::move(hash));
        if (!inserted) {
            throw std::runtime_error(
                "duplicate username in password file at line " + std::to_string(line_no)
            );
        }
    }

    return users;
}

static bool verify_bcrypt_password(
    std::string_view password,
    std::string_view bcrypt_hash
) {
    if (!is_bcrypt_hash(bcrypt_hash)) {
        return false;
    }

    struct crypt_data data {};
    data.initialized = 0;

    std::string pwd(password);
    std::string hash(bcrypt_hash);

    char* out = ::crypt_r(pwd.c_str(), hash.c_str(), &data);
    if (!out) {
        return false;
    }

    return hash == out;
}

static Config load_config(const std::string& path) {
    Config cfg;
    std::ifstream in(path);
    if (!in) {
        throw std::runtime_error("cannot open config: " + path);
    }

    std::string line;
    std::size_t line_no = 0;

    while (std::getline(in, line)) {
        ++line_no;
        line = trim(line);

        if (line.empty() || line[0] == '#') {
            continue;
        }

        auto eq = line.find('=');
        if (eq == std::string::npos) {
            throw std::runtime_error("invalid config line " + std::to_string(line_no));
        }

        std::string key = trim(line.substr(0, eq));
        std::string val = trim(line.substr(eq + 1));

        if (key == "listen") {
            cfg.listen = val;
        } else if (key == "port") {
            cfg.port = static_cast<std::uint16_t>(std::stoul(val));
        } else if (key == "password_file") {
            cfg.password_file = val;
        } else if (key == "user") {
            throw std::runtime_error(
                "plaintext 'user=' entries are not supported; use password_file"
            );
        } else {
            throw std::runtime_error(
                "unknown config key at line " + std::to_string(line_no) + ": " + key
            );
        }
    }

    if (cfg.password_file.empty()) {
        throw std::runtime_error("password_file must be set in proxy.conf");
    }

    cfg.users = load_password_file(cfg.password_file);

    if (cfg.users.empty()) {
        throw std::runtime_error("password file contains no users");
    }

    return cfg;
}

static std::string base64_decode(std::string_view input) {
    static constexpr std::array<int, 256> table = [] {
        std::array<int, 256> t{};
        t.fill(-1);

        for (int i = 'A'; i <= 'Z'; ++i) t[static_cast<unsigned char>(i)] = i - 'A';
        for (int i = 'a'; i <= 'z'; ++i) t[static_cast<unsigned char>(i)] = i - 'a' + 26;
        for (int i = '0'; i <= '9'; ++i) t[static_cast<unsigned char>(i)] = i - '0' + 52;

        t[static_cast<unsigned char>('+')] = 62;
        t[static_cast<unsigned char>('/')] = 63;
        return t;
    }();

    std::string out;
    int val = 0;
    int valb = -8;

    for (unsigned char c : input) {
        if (c == '=') {
            break;
        }

        int d = table[c];
        if (d == -1) {
            continue;
        }

        val = (val << 6) | d;
        valb += 6;

        if (valb >= 0) {
            out.push_back(static_cast<char>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }

    return out;
}

static std::optional<std::pair<std::string, std::string>>
extract_basic_credentials(const http::request<http::string_body>& req) {
    auto it = req.find(http::field::proxy_authorization);
    if (it == req.end()) {
        return std::nullopt;
    }

    std::string header = sv_to_string(it->value());
    constexpr std::string_view prefix = "Basic ";

    if (header.size() < prefix.size()) {
        return std::nullopt;
    }

    if (!boost::iequals(header.substr(0, prefix.size()), std::string(prefix))) {
        return std::nullopt;
    }

    std::string decoded = base64_decode(std::string_view(header).substr(prefix.size()));
    auto colon = decoded.find(':');
    if (colon == std::string::npos) {
        return std::nullopt;
    }

    return std::make_pair(decoded.substr(0, colon), decoded.substr(colon + 1));
}

static bool authorized(const http::request<http::string_body>& req, const Config& cfg) {
    auto creds = extract_basic_credentials(req);
    if (!creds) {
        return false;
    }

    auto it = cfg.users.find(creds->first);
    if (it == cfg.users.end()) {
        return false;
    }

    return verify_bcrypt_password(creds->second, it->second);
}

static void send_simple_response(
    tcp::socket& sock,
    http::status st,
    unsigned version,
    std::string body,
    bool close,
    std::optional<std::string> proxy_authenticate = std::nullopt
) {
    http::response<http::string_body> res{st, version};
    res.set(http::field::server, "cpp-proxy");
    res.set(http::field::content_type, "text/plain; charset=utf-8");
    if (proxy_authenticate) {
        res.set(http::field::proxy_authenticate, *proxy_authenticate);
    }
    res.keep_alive(!close);
    res.body() = std::move(body);
    res.prepare_payload();
    http::write(sock, res);
}

static std::pair<std::string, std::string>
split_host_port(std::string s, std::string default_port) {
    s = trim(std::move(s));

    if (s.empty()) {
        return {"", std::move(default_port)};
    }

    if (s.front() == '[') {
        auto end = s.find(']');
        if (end == std::string::npos) {
            return {s, std::move(default_port)};
        }

        std::string host = s.substr(1, end - 1);
        if (end + 1 < s.size() && s[end + 1] == ':') {
            return {host, s.substr(end + 2)};
        }
        return {host, std::move(default_port)};
    }

    auto first_colon = s.find(':');
    auto last_colon  = s.rfind(':');

    if (first_colon != std::string::npos && first_colon == last_colon) {
        return {s.substr(0, first_colon), s.substr(first_colon + 1)};
    }

    return {s, std::move(default_port)};
}

static std::optional<UpstreamTarget>
parse_forward_target(const http::request<http::string_body>& req) {
    std::string t = sv_to_string(req.target());

    auto parse_absolute = [&](std::string_view scheme, std::string default_port)
        -> std::optional<UpstreamTarget>
    {
        std::string prefix = std::string(scheme) + "://";
        if (!boost::istarts_with(t, prefix)) {
            return std::nullopt;
        }

        std::size_t authority_start = prefix.size();
        std::size_t path_pos = t.find('/', authority_start);

        std::string authority = path_pos == std::string::npos
            ? t.substr(authority_start)
            : t.substr(authority_start, path_pos - authority_start);

        std::string path = path_pos == std::string::npos ? "/" : t.substr(path_pos);

        auto [host, port] = split_host_port(authority, std::move(default_port));
        if (host.empty()) {
            return std::nullopt;
        }

        return UpstreamTarget{std::move(host), std::move(port), std::move(path)};
    };

    if (auto u = parse_absolute("http", "80")) {
        return u;
    }
    if (auto u = parse_absolute("https", "443")) {
        return u;
    }

    if (!t.empty() && t.front() == '/') {
        auto host_it = req.find(http::field::host);
        if (host_it == req.end()) {
            return std::nullopt;
        }

        auto [host, port] = split_host_port(sv_to_string(host_it->value()), "80");
        if (host.empty()) {
            return std::nullopt;
        }

        return UpstreamTarget{std::move(host), std::move(port), std::move(t)};
    }

    return std::nullopt;
}

static void relay_stream(tcp::socket& from, tcp::socket& to) {
    std::array<char, 8192> buf{};

    for (;;) {
        boost::system::error_code ec;
        std::size_t n = from.read_some(asio::buffer(buf), ec);

        if (ec == asio::error::eof || ec == asio::error::connection_reset) {
            break;
        }
        if (ec) {
            break;
        }

        asio::write(to, asio::buffer(buf.data(), n), ec);
        if (ec) {
            break;
        }
    }

    boost::system::error_code ignored;
    to.shutdown(tcp::socket::shutdown_send, ignored);
}

static bool handle_connect(
    tcp::socket& client,
    asio::io_context& ioc,
    const http::request<http::string_body>& req
) {
    auto [host, port] = split_host_port(sv_to_string(req.target()), "443");
    if (host.empty()) {
        send_simple_response(
            client,
            http::status::bad_request,
            req.version(),
            "Invalid CONNECT target\n",
            true
        );
        return false;
    }

    try {
        tcp::resolver resolver(ioc);
        auto endpoints = resolver.resolve(host, port);

        tcp::socket upstream = connect_with_timeout_posix(ioc, endpoints, kUpstreamConnectTimeout);
        apply_socket_timeouts(upstream, kTunnelIdleTimeout, kTunnelIdleTimeout);
        apply_socket_timeouts(client,   kTunnelIdleTimeout, kTunnelIdleTimeout);

        http::response<http::empty_body> res{http::status::ok, req.version()};
        res.set(http::field::server, "cpp-proxy");
        res.keep_alive(false);
        http::write(client, res);

        std::jthread t1([&] { relay_stream(client, upstream); });
        std::jthread t2([&] { relay_stream(upstream, client); });

        return false;
    } catch (const std::exception& e) {
        send_simple_response(
            client,
            http::status::bad_gateway,
            req.version(),
            std::string("CONNECT failed: ") + e.what() + "\n",
            true
        );
        return false;
    }
}

static bool handle_forward(
    tcp::socket& client,
    asio::io_context& ioc,
    http::request<http::string_body> req
) {
    auto dst = parse_forward_target(req);
    if (!dst) {
        send_simple_response(
            client,
            http::status::bad_request,
            req.version(),
            "Proxy request must use absolute URI or include Host header\n",
            true
        );
        return false;
    }

    try {
        tcp::resolver resolver(ioc);
        auto endpoints = resolver.resolve(dst->host, dst->port);

        tcp::socket upstream = connect_with_timeout_posix(ioc, endpoints, kUpstreamConnectTimeout);
        apply_socket_timeouts(upstream, kUpstreamReadTimeout, kUpstreamWriteTimeout);

        http::request<http::string_body> out{req.method(), dst->target, req.version()};
        out.version(req.version());
        out.keep_alive(req.keep_alive());

        for (auto const& field : req) {
            if (field.name() == http::field::proxy_authorization) {
                continue;
            }
            if (iequals_sv(field.name_string(), "Proxy-Connection")) {
                continue;
            }

            out.set(field.name_string(), field.value());
        }

        if (!out.count(http::field::host)) {
            if (dst->port == "80" || dst->port == "443") {
                out.set(http::field::host, dst->host);
            } else {
                out.set(http::field::host, dst->host + ":" + dst->port);
            }
        }

        out.body() = std::move(req.body());
        out.prepare_payload();

        http::write(upstream, out);

        beast::flat_buffer upstream_buffer;
        http::response<http::string_body> resp;
        http::read(upstream, upstream_buffer, resp);

        http::write(client, resp);
        return req.keep_alive() && resp.keep_alive();
    } catch (const std::exception& e) {
        send_simple_response(
            client,
            http::status::bad_gateway,
            req.version(),
            std::string("Upstream request failed: ") + e.what() + "\n",
            true
        );
        return false;
    }
}

static void session(tcp::socket client, const Config& cfg) {
    try {
        const auto remote = client.remote_endpoint();
        auto& ioc = static_cast<asio::io_context&>(client.get_executor().context());
        beast::flat_buffer buffer;

        apply_socket_timeouts(client, kClientReadTimeout, kClientWriteTimeout);

        for (;;) {
            http::request<http::string_body> req;
            boost::system::error_code ec;
            http::read(client, buffer, req, ec);

            if (ec == http::error::end_of_stream || ec == asio::error::eof) {
                break;
            }
            if (ec) {
                std::cerr << "read error from " << endpoint_to_string(remote)
                          << ": " << ec.message() << "\n";
                break;
            }

            if (!authorized(req, cfg)) {
                send_simple_response(
                    client,
                    http::status::proxy_authentication_required,
                    req.version(),
                    "Proxy authentication required\n",
                    true,
                    "Basic realm=\"cpp-proxy\""
                );
                break;
            }

            std::cerr << endpoint_to_string(remote)
                      << " " << sv_to_string(req.method_string())
                      << " " << sv_to_string(req.target()) << "\n";

            if (req.method() == http::verb::connect) {
                handle_connect(client, ioc, req);
                break;
            }

            if (!handle_forward(client, ioc, std::move(req))) {
                break;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "session error: " << e.what() << "\n";
    }

    boost::system::error_code ignored;
    client.shutdown(tcp::socket::shutdown_both, ignored);
    client.close(ignored);
}

int main(int argc, char** argv) {
    std::signal(SIGPIPE, SIG_IGN);

    try {
        const std::string config_path = argc > 1 ? argv[1] : "proxy.conf";
        const Config cfg = load_config(config_path);

        asio::io_context ioc(1);
        tcp::endpoint endpoint{asio::ip::make_address(cfg.listen), cfg.port};

        tcp::acceptor acceptor(ioc);
        acceptor.open(endpoint.protocol());
        acceptor.set_option(asio::socket_base::reuse_address(true));
        acceptor.bind(endpoint);
        acceptor.listen(asio::socket_base::max_listen_connections);

        std::cerr << "Listening on " << cfg.listen << ":" << cfg.port << "\n";

        for (;;) {
            tcp::socket client(ioc);
            acceptor.accept(client);

            std::thread(
                [cfg, s = std::move(client)]() mutable {
                    session(std::move(s), cfg);
                }
            ).detach();
        }
    } catch (const std::exception& e) {
        std::cerr << "fatal: " << e.what() << "\n";
        return 1;
    }

    return 0;
}

