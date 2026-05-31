#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <linux/netfilter_ipv4.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <time.h>

const char *LOG_DIR = "./log";
const int DIRECT_MARK = 0x0416;
const size_t BUF_SIZE = 128;

static volatile sig_atomic_t should_stop = 0;
void signal_handler_stop(int signum) { should_stop = 1; }

void format_addr(const struct sockaddr_in *addr, char *res, size_t len) {
    snprintf(res, len, "%s:%d", inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
}

void log_info(const char *fmt, ...) {
    va_list(args);
    va_start(args, fmt);

    char msg[BUF_SIZE];
    vsnprintf(msg, sizeof(msg), fmt, args);
    printf("[INFO] %s\n", msg);

    va_end(args);
}

void log_info_pid(const char *fmt, ...) {
    va_list(args);
    va_start(args, fmt);

    char msg[BUF_SIZE];
    vsnprintf(msg, sizeof(msg), fmt, args);
    printf("[INFO pid=%d] %s\n", getpid(), msg);

    va_end(args);
}

void log_error(const char *fmt, ...) {
    va_list(args);
    va_start(args, fmt);

    char msg[BUF_SIZE];
    vsnprintf(msg, sizeof(msg), fmt, args);
    printf("[ERROR] %s\n", msg);

    va_end(args);
}

void log_error_info(const char *fmt, ...) {
    va_list(args);
    va_start(args, fmt);

    char msg[BUF_SIZE];
    vsnprintf(msg, sizeof(msg), fmt, args);
    printf("[ERROR name=%s desc=\"%s\"] %s\n", strerrorname_np(errno), strerrordesc_np(errno), msg);

    va_end(args);
}

void log_error_info_pid(const char *fmt, ...) {
    va_list(args);
    va_start(args, fmt);

    char msg[BUF_SIZE];
    vsnprintf(msg, sizeof(msg), fmt, args);
    printf("[ERROR pid=%d name=%s desc=\"%s\"] %s\n", getpid(), strerrorname_np(errno), strerrordesc_np(errno), msg);

    va_end(args);
}

int set_signal_handler() {
    struct sigaction sa;
    sa.sa_handler = signal_handler_stop;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGINT, &sa, NULL) < 0 || sigaction(SIGTERM, &sa, NULL) < 0) {
        perror("sigaction() failed");
        return -1;
    }
    return 0;
}

bool _nftable_created;
int setup_nftables(int port) {
    int ret;

    if ((ret = system("nft add table ip chocomint")) != 0) return ret;

    _nftable_created = true;

    if ((ret = system("nft 'add chain ip chocomint output { type nat hook output priority mangle + 1; policy accept; }'")) != 0) return ret;

    if ((ret = system("nft add rule ip chocomint output meta mark 0x00000416 counter return")) != 0) return ret;

    char cmd[128];
    sprintf(cmd, "nft add rule ip chocomint output meta l4proto tcp counter redirect to :%d", port);
    if ((ret = system(cmd)) != 0) return ret;

    return 0;
}
void cleanup_nftables() {
    if (_nftable_created) system("nft delete table ip chocomint");
}

int handle_connection(int client_fd, const struct sockaddr_in *src_addr, const struct sockaddr_in *dst_addr) {
    char src_addr_str[BUF_SIZE], dst_addr_str[BUF_SIZE];
    int server_fd;
    char log_filename[BUF_SIZE];
    FILE *log_fp;
    int epoll_fd;
    struct epoll_event ev;
    ssize_t up_bytes, down_bytes;

    format_addr(src_addr, src_addr_str, sizeof(src_addr_str));
    format_addr(dst_addr, dst_addr_str, sizeof(dst_addr_str));
    log_info_pid("new connection %s -> %s", src_addr_str, dst_addr_str);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        log_error_info_pid("socket() failed");
        goto EXIT;
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_MARK, &DIRECT_MARK, sizeof(DIRECT_MARK)) < 0) {
        log_error_info_pid("setsockopt() failed");
        goto EXIT_SERVER_FD;
    }

    if (connect(server_fd, (const struct sockaddr *)dst_addr, sizeof(*dst_addr))) {
        log_error_info_pid("connect() failed");
        goto EXIT_SERVER_FD;
    }

    if (mkdir(LOG_DIR, 0755) < 0) {
        if (errno == EEXIST) log_info_pid("log dir already existed");
        else log_error_info_pid("mkdir() failed");
    }
    sprintf(log_filename, "%s/%ld_%s_to_%s.log", LOG_DIR, time(NULL), src_addr_str, dst_addr_str);
    log_fp = fopen(log_filename, "wb");
    if (!log_fp) {
        log_error_info_pid("fopen() failed");
        goto EXIT_SERVER_FD;
    }

    epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        log_error_info_pid("epoll_create1() failed");
        goto EXIT_LOG_FP;
    }

    ev.events = EPOLLIN;
    ev.data.fd = client_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev) < 0) {
        log_error_info_pid("failed to add client epoll event");
        goto EXIT_EPOLL_FD;
    }

    ev.events = EPOLLIN;
    ev.data.fd = server_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev) < 0) {
        log_error_info_pid("failed to add server epoll event");
        goto EXIT_EPOLL_FD;
    }

    while (true) {
        struct epoll_event e[2];
        int ne;
        char buf[4096];

        ne = epoll_wait(epoll_fd, e, 2, -1);
        if (ne < 0) {
            log_error_info_pid("epoll_wait() failed");
            goto EXIT_EPOLL;
        }

        for (int i = 0; i < ne; i++) {
            ssize_t n, m;
            int cfd = e[i].data.fd;

            if (cfd == client_fd) {
                n = read(client_fd, buf, sizeof(buf));
                if (n <= 0) {
                    if (n < 0) log_error_info_pid("read() failed on client");
                    goto EXIT_EPOLL;
                }
                up_bytes += n;

                m = write(server_fd, buf, n);
                if (m != n) {
                    log_error_info_pid("write() failed on server");
                    goto EXIT_EPOLL;
                }

                fprintf(log_fp, ">>> %lu bytes\n", n);
                fwrite(buf, sizeof(char), n, log_fp);
                fputc('\n', log_fp);
            } else if (cfd == server_fd) {
                n = read(server_fd, buf, sizeof(buf));
                if (n <= 0) {
                    if (n < 0) log_error_info_pid("read() failed on server");
                    goto EXIT_EPOLL;
                }
                down_bytes += n;

                m = write(client_fd, buf, n);
                if (m != n) {
                    log_error_info_pid("write() failed on client");
                    goto EXIT_EPOLL;
                }

                fprintf(log_fp, "<<< %lu bytes\n", n);
                fwrite(buf, sizeof(char), n, log_fp);
                fputc('\n', log_fp);
            }
        }

        continue;
    EXIT_EPOLL:
        break;
    }

    log_info_pid("connection %s -> %s closed >>>%lu <<<%lu", src_addr_str, dst_addr_str, up_bytes, down_bytes);

EXIT_EPOLL_FD:
    close(epoll_fd);
EXIT_LOG_FP:
    fclose(log_fp);
EXIT_SERVER_FD:
    close(server_fd);
EXIT:
    exit(0);
}

int main(int argc, char **argv) {
    if (set_signal_handler() < 0) return 1;

    int listen_fd;
    struct sockaddr_in listen_addr;
    socklen_t listen_addr_len = sizeof(listen_addr);
    char listen_addr_str[32];
    int listen_port;

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        log_error_info("socket() failed");
        goto EXIT;
    }

    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    listen_addr.sin_port = htonl(0);
    if (bind(listen_fd, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
        log_error_info("bind() failed");
        goto EXIT_LISTEN_FD;
    }

    if (listen(listen_fd, 16) < 0) {
        log_error_info("listen() failed");
        goto EXIT_LISTEN_FD;
    }

    if (getsockname(listen_fd, (struct sockaddr *)&listen_addr, &listen_addr_len) < 0) {
        log_error_info("getsockname() failed");
        goto EXIT_LISTEN_FD;
    }

    format_addr(&listen_addr, listen_addr_str, sizeof(listen_addr_str));
    log_info("listen on %s", listen_addr_str);

    listen_port = ntohs(listen_addr.sin_port);

    if (setup_nftables(listen_port) != 0) {
        log_error("failed to setup nftables");
        goto EXIT_NFTABLES;
    }

    while (!should_stop) {
        int client_fd;
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        struct sockaddr_in server_addr;
        socklen_t server_addr_len = sizeof(server_addr);
        pid_t pid;

        client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_fd < 0) {
            log_error_info("accept() failed");
            continue;
        }

        if (getsockopt(client_fd, SOL_IP, SO_ORIGINAL_DST, &server_addr, &server_addr_len)) {
            log_error_info("getsockopt() failed");
            continue;
        }

        pid = fork();
        if (pid < 0) {
            log_error_info("fork() failed");
            goto EXIT_CLIENT_FD;
        }

        if (pid == 0) {
            close(listen_fd);
            handle_connection(client_fd, &client_addr, &server_addr);
        }

    EXIT_CLIENT_FD:
        close(client_fd);
    }

EXIT_NFTABLES:
    cleanup_nftables();
EXIT_LISTEN_FD:
    close(listen_fd);
EXIT:
    return 0;
}