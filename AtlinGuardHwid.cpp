#define ATLINGUARD_HWID_BUILD
#include "AtlinGuardHwid.h"

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>

#include <atomic>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")

namespace {
    constexpr wchar_t kSection[] = L"AtlinGuardHwid";
    constexpr std::size_t kMaxTokenFile = 4096;
    constexpr std::size_t kMinToken = 32;
    constexpr std::size_t kMaxToken = 256;
    constexpr std::size_t kMaxAccountBytes = 64;
    constexpr std::size_t kMaxPeer = 64;
    constexpr std::size_t kQueueLimit = 1024;

    // Result of the last report, read by AtgHwid_LastStatus.
    std::atomic<int> g_lastStatus(ATG_HWID_STATUS_NONE);

    // The TenantServer rejects control characters in an account, so only the two JSON string delimiters need escaping; anything else invalid is refused there.
    std::string Json(const std::string& value) {
        std::string output;
        output.reserve(value.size() + 8);
        for (const char c : value) {
            if (c == '\\' || c == '"') output += '\\';
            output += c;
        }
        return output;
    }

    // Bounded queue drained by one worker thread. It exposes no enforcement result: Observe only queues a best-effort history observation.
    class Reporter final {
        public:
            struct Config {
                unsigned short port = 28930;
                std::wstring bearerToken;
            };

            explicit Reporter(Config config) : config_(std::move(config)) {}
            ~Reporter() { Stop(); }
            Reporter(const Reporter&) = delete;
            Reporter& operator=(const Reporter&) = delete;

            // Fails only when the worker thread cannot be created; the configuration is already valid.
            bool Start() {
                std::lock_guard<std::mutex> lock(mutex_);
                if (running_) return false;
                stop_ = false;
                running_ = true;
                try {
                    worker_ = std::thread(&Reporter::Run, this);
                } catch (...) {
                    running_ = false;
                    return false;
                }
                return true;
            }

            // Waits for the worker, so it must never run under the loader lock (DllMain).
            void Stop() {
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    if (!running_) return;
                    stop_ = true;
                }
                wake_.notify_all();
                if (worker_.joinable()) worker_.join();
                std::lock_guard<std::mutex> lock(mutex_);
                running_ = false;
            }

            void Observe(std::string account, std::string gatewayPeer) {
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    if (!running_ || stop_ || queue_.size() >= kQueueLimit) return;
                    try {
                        queue_.push_back({std::move(account), std::move(gatewayPeer)});
                    } catch (...) {
                        return;
                    }
                }
                wake_.notify_one();
            }

        private:
            struct Observation {
                std::string account;
                std::string gatewayPeer;
            };

            void Run() {
                for (;;) {
                    Observation observation;
                    {
                        std::unique_lock<std::mutex> lock(mutex_);
                        wake_.wait(lock, [this] { return stop_ || !queue_.empty(); });
                        if (stop_) return;
                        observation = std::move(queue_.front());
                        queue_.pop_front();
                    }
                    try {
                        g_lastStatus.store(Post("{\"version\":1,\"account\":\"" + Json(observation.account)
                            + "\",\"gatewayPeer\":\"" + Json(observation.gatewayPeer) + "\"}"));
                    } catch (...) {
                        // Drop this optional observation and keep the worker alive.
                    }
                }
            }

            // One attempt per observation: on loopback a failed delivery means the TenantServer is down, and an immediate retry would not change that. Returns the HTTP status, or ATG_HWID_STATUS_UNREACHABLE when no response arrived.
            int Post(const std::string& body) const {
                int status = ATG_HWID_STATUS_UNREACHABLE;
                HINTERNET session = WinHttpOpen(L"AtlinGuard-L2OFF-Hwid/1",
                    WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
                if (!session) return status;
                WinHttpSetTimeouts(session, 2000, 2000, 2000, 2000);
                HINTERNET connection = WinHttpConnect(session, L"127.0.0.1", config_.port, 0);
                HINTERNET request = connection ? WinHttpOpenRequest(connection, L"POST",
                    L"/internal/v1/account-hwid/login", nullptr, WINHTTP_NO_REFERER,
                    WINHTTP_DEFAULT_ACCEPT_TYPES, 0) : nullptr;
                const std::wstring headers = L"Authorization: Bearer " + config_.bearerToken
                    + L"\r\nContent-Type: application/json\r\n";
                if (request && WinHttpSendRequest(request, headers.c_str(), static_cast<DWORD>(-1),
                        const_cast<char*>(body.data()), static_cast<DWORD>(body.size()),
                        static_cast<DWORD>(body.size()), 0)
                    && WinHttpReceiveResponse(request, nullptr)) {
                    DWORD code = 0;
                    DWORD size = sizeof(code);
                    if (WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &code, &size, WINHTTP_NO_HEADER_INDEX)) {
                        status = static_cast<int>(code);
                    }
                }
                if (request) WinHttpCloseHandle(request);
                if (connection) WinHttpCloseHandle(connection);
                WinHttpCloseHandle(session);
                return status;
            }

            Config config_;
            std::mutex mutex_;
            std::condition_variable wake_;
            std::deque<Observation> queue_;
            std::thread worker_;
            bool running_ = false;
            bool stop_ = false;
    };

    std::mutex g_mutex;
    // getpeername needs Winsock in this module's view even if the host initialized it already.
    bool g_winsock = false;

    // Deliberately never destroyed: a destructor at process exit would wait for the worker under the loader lock. AtgHwid_Stop is the only place that stops the reporter.
    std::shared_ptr<Reporter>& ReporterSlot() {
        static auto* const slot = new std::shared_ptr<Reporter>();
        return *slot;
    }

    std::shared_ptr<Reporter> CurrentReporter() {
        std::lock_guard<std::mutex> lock(g_mutex);
        return ReporterSlot();
    }

    // Same rule as the TenantServer, which reads the same file: surrounding whitespace is ignored and the token has 32 to 256 characters. The DLL also requires ASCII without control characters, because the token travels in an HTTP header.
    bool ReadToken(const std::wstring& path, std::wstring& token) {
        const HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) return false;
        char buffer[kMaxTokenFile + 1];
        DWORD read = 0;
        const BOOL ok = ReadFile(file, buffer, static_cast<DWORD>(sizeof(buffer)), &read, nullptr);
        CloseHandle(file);
        if (!ok || read == 0 || read > kMaxTokenFile) {
            SecureZeroMemory(buffer, sizeof(buffer));
            return false;
        }
        std::size_t begin = 0;
        std::size_t end = read;
        const auto space = [](const char c) {
            return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f';
        };
        while (begin < end && space(buffer[begin])) ++begin;
        while (end > begin && space(buffer[end - 1])) --end;
        bool valid = end - begin >= kMinToken && end - begin <= kMaxToken;
        token.clear();
        for (std::size_t i = begin; valid && i < end; ++i) {
            const unsigned char c = static_cast<unsigned char>(buffer[i]);
            if ((c < 0x20 && c != '\t') || c > 0x7e) valid = false;
            else token.push_back(static_cast<wchar_t>(c));
        }
        SecureZeroMemory(buffer, sizeof(buffer));
        if (!valid) {
            SecureZeroMemory(&token[0], token.size() * sizeof(wchar_t));
            token.clear();
            return false;
        }
        return true;
    }

    bool ReadConfig(const wchar_t* path, Reporter::Config& config) {
        if (path == nullptr || path[0] == L'\0') return false;
        // The profile API looks for a bare file name in the Windows directory, not in the current one, so resolve the path first.
        wchar_t fullPath[MAX_PATH] = {};
        const DWORD fullLength = GetFullPathNameW(path, MAX_PATH, fullPath, nullptr);
        if (fullLength == 0 || fullLength >= MAX_PATH) return false;
        const DWORD attributes = GetFileAttributesW(fullPath);
        if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) return false;
        const UINT port = GetPrivateProfileIntW(kSection, L"Port", 28930, fullPath);
        if (port == 0 || port > 65535) return false;
        wchar_t tokenFile[MAX_PATH] = {};
        const DWORD tokenFileLength = GetPrivateProfileStringW(kSection, L"TokenFile", L"",
            tokenFile, MAX_PATH, fullPath);
        if (tokenFileLength == 0 || tokenFileLength >= MAX_PATH - 1) return false;
        config.port = static_cast<unsigned short>(port);
        return ReadToken(tokenFile, config.bearerToken);
    }

    bool Utf8Account(const wchar_t* account, std::string& output) {
        if (account == nullptr) return false;
        // A login name is short; bound the scan so a missing terminator cannot run away.
        std::size_t length = 0;
        while (length <= kMaxAccountBytes && account[length] != L'\0') ++length;
        if (length == 0 || length > kMaxAccountBytes) return false;
        char buffer[kMaxAccountBytes * 4];
        const int written = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, account,
            static_cast<int>(length), buffer, static_cast<int>(sizeof(buffer)), nullptr, nullptr);
        if (written <= 0 || static_cast<std::size_t>(written) > kMaxAccountBytes) return false;
        output.assign(buffer, static_cast<std::size_t>(written));
        return true;
    }

    // Formats an address the way the gateway registry knows it: "a.b.c.d:port" or "[ipv6]:port".
    // A dual-stack socket reports an IPv4 gateway as ::ffff:a.b.c.d, so that form becomes IPv4.
    bool FormatPeer(int family, const void* address, unsigned short port, std::string& peer) {
        if (port == 0) return false;
        char text[INET6_ADDRSTRLEN] = {};
        if (family == AF_INET6 && IN6_IS_ADDR_V4MAPPED(static_cast<const in6_addr*>(address))) {
            family = AF_INET;
            address = &static_cast<const in6_addr*>(address)->s6_addr[12];
        }
        if (inet_ntop(family, const_cast<void*>(address), text, sizeof(text)) == nullptr) return false;
        peer = family == AF_INET6 ? "[" + std::string(text) + "]" : std::string(text);
        peer += ":" + std::to_string(port);
        return true;
    }

    bool SocketPeer(UINT_PTR handle, std::string& peer) {
        sockaddr_storage address = {};
        int size = static_cast<int>(sizeof(address));
        if (getpeername(static_cast<SOCKET>(handle), reinterpret_cast<sockaddr*>(&address), &size) != 0) {
            return false;
        }
        if (address.ss_family == AF_INET) {
            const auto* v4 = reinterpret_cast<const sockaddr_in*>(&address);
            return FormatPeer(AF_INET, &v4->sin_addr, ntohs(v4->sin_port), peer);
        }
        if (address.ss_family == AF_INET6) {
            const auto* v6 = reinterpret_cast<const sockaddr_in6*>(&address);
            return FormatPeer(AF_INET6, &v6->sin6_addr, ntohs(v6->sin6_port), peer);
        }
        return false;
    }

    // Accepts only "a.b.c.d:port" or "[ipv6]:port" and returns it in the canonical form.
    bool ValidPeer(const char* value, std::string& peer) {
        if (value == nullptr) return false;
        std::size_t length = 0;
        while (length <= kMaxPeer && value[length] != '\0') ++length;
        if (length == 0 || length > kMaxPeer) return false;
        const std::string text(value, length);
        const std::size_t colon = text.rfind(':');
        if (colon == std::string::npos || colon == 0 || colon + 1 == length || length - colon > 6) return false;
        unsigned long port = 0;
        for (std::size_t i = colon + 1; i < length; ++i) {
            if (text[i] < '0' || text[i] > '9') return false;
            port = port * 10 + static_cast<unsigned long>(text[i] - '0');
        }
        if (port == 0 || port > 65535) return false;
        std::string host = text.substr(0, colon);
        if (host.size() > 2 && host.front() == '[' && host.back() == ']') {
            in6_addr v6 = {};
            host = host.substr(1, host.size() - 2);
            if (inet_pton(AF_INET6, host.c_str(), &v6) != 1) return false;
            return FormatPeer(AF_INET6, &v6, static_cast<unsigned short>(port), peer);
        }
        in_addr v4 = {};
        if (inet_pton(AF_INET, host.c_str(), &v4) != 1) return false;
        return FormatPeer(AF_INET, &v4, static_cast<unsigned short>(port), peer);
    }

    void Observe(const std::shared_ptr<Reporter>& reporter, const wchar_t* account, std::string peer) {
        std::string name;
        if (!Utf8Account(account, name)) return;
        reporter->Observe(std::move(name), std::move(peer));
    }
} // namespace

extern "C" int ATG_HWID_CALL AtgHwid_Start(const wchar_t* configPath) {
    try {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto& slot = ReporterSlot();
        if (slot) return ATG_HWID_ALREADY_STARTED;
        Reporter::Config config;
        if (!ReadConfig(configPath, config)) return ATG_HWID_CONFIG_INVALID;
        // The worker runs this module's code until the process exits.
        HMODULE self = nullptr;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                reinterpret_cast<LPCWSTR>(&AtgHwid_Start), &self)) {
            return ATG_HWID_START_FAILED;
        }
        WSADATA winsock;
        if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) return ATG_HWID_START_FAILED;
        auto reporter = std::make_shared<Reporter>(std::move(config));
        if (!reporter->Start()) {
            WSACleanup();
            return ATG_HWID_START_FAILED;
        }
        g_winsock = true;
        g_lastStatus.store(ATG_HWID_STATUS_NONE);
        slot = std::move(reporter);
        return ATG_HWID_STARTED;
    } catch (...) {
        return ATG_HWID_START_FAILED;
    }
}

extern "C" void ATG_HWID_CALL AtgHwid_Stop(void) {
    try {
        std::shared_ptr<Reporter> reporter;
        bool winsock = false;
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            reporter.swap(ReporterSlot());
            winsock = g_winsock;
            g_winsock = false;
        }
        if (reporter) reporter->Stop();
        if (winsock) WSACleanup();
    } catch (...) {
        // Shutdown must never fail the host.
    }
}

extern "C" void ATG_HWID_CALL AtgHwid_ObserveAuthenticated(
    const wchar_t* account,
    UINT_PTR socketHandle) {
    try {
        const auto reporter = CurrentReporter();
        if (!reporter) return;
        std::string peer;
        if (!SocketPeer(socketHandle, peer)) return;
        Observe(reporter, account, std::move(peer));
    } catch (...) {
        // An optional observation must never fail the login.
    }
}

extern "C" void ATG_HWID_CALL AtgHwid_ObserveAuthenticatedPeer(
    const wchar_t* account,
    const char* gatewayPeer) {
    try {
        const auto reporter = CurrentReporter();
        if (!reporter) return;
        std::string peer;
        if (!ValidPeer(gatewayPeer, peer)) return;
        Observe(reporter, account, std::move(peer));
    } catch (...) {
        // An optional observation must never fail the login.
    }
}

extern "C" int ATG_HWID_CALL AtgHwid_LastStatus(void) {
    return g_lastStatus.load();
}
