#include <arpa/inet.h>
#include <linux/netfilter_ipv4.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

const char *LOG_DIR = "./log";
const int DIRECT_MARK = 0x0416;

static volatile sig_atomic_t should_stop = 0;
void signal_handler_stop(int signum) { should_stop = 1; }
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

void format_addr(const struct sockaddr_in *addr, char *res, size_t len) {
    snprintf(res, len, "%s:%d", inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
}

int setup_nftables(int port) {
    int ret;

    if ((ret = system("nft add table ip chocomint")) != 0) return ret;

    if ((ret = system("nft 'add chain ip chocomint output { type nat hook output priority mangle + 1; policy accept; }'")) != 0) return ret;

    if ((ret = system("nft add rule ip chocomint output meta mark 0x00000416 counter return")) != 0) return ret;

    char cmd[128];
    sprintf(cmd, "nft add rule ip chocomint output meta l4proto tcp counter redirect to :%d", port);
    if ((ret = system(cmd)) != 0) return ret;

    return 0;
}

void cleanup_nftables() { system("nft delete table ip chocomint"); }

int handle_connection(int client_fd, const struct sockaddr_in *src_addr, const struct sockaddr_in *dst_addr) {
    int connid;
    char errmsg[64];
    char src_addr_str[64], dst_addr_str[64];
    int server_fd;
    char log_filename[256];
    FILE *log_fp;
    int epoll_fd;
    struct epoll_event ev;
    ssize_t up_bytes, down_bytes;

    connid = rand();

    format_addr(src_addr, src_addr_str, sizeof(src_addr_str));
    format_addr(dst_addr, dst_addr_str, sizeof(dst_addr_str));
    printf("[%d] New connection: %s -> %s\n", connid, src_addr_str, dst_addr_str);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        sprintf(errmsg, "[%d] socket() failed", connid);
        perror(errmsg);

        exit(1);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_MARK, &DIRECT_MARK, sizeof(DIRECT_MARK)) < 0) {
        sprintf(errmsg, "[%d] setsockopt() failed", connid);
        perror(errmsg);

        close(server_fd);
        exit(1);
    }

    if (connect(server_fd, (const struct sockaddr *)dst_addr, sizeof(*dst_addr))) {
        sprintf(errmsg, "[%d] connect() failed", connid);
        perror(errmsg);

        close(server_fd);
        exit(1);
    }

    sprintf(log_filename, "%s/%d_%s_to_%s.log", LOG_DIR, connid, src_addr_str, dst_addr_str);

    mkdir(LOG_DIR, 0755);

    log_fp = fopen(log_filename, "wb");
    if (!log_fp) {
        sprintf(errmsg, "[%d] fopen() failed", connid);
        perror(errmsg);

        close(server_fd);
        exit(1);
    }
    if ((epoll_fd = epoll_create1(0)) < 0) {
        sprintf(errmsg, "[%d] epoll_create1() failed", connid);
        perror(errmsg);

        fclose(log_fp);
        close(server_fd);
        exit(1);
    }

    ev.events = EPOLLIN;
    ev.data.fd = client_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev) < 0) {
        sprintf(errmsg, "[%d], epoll_ctl() failed", connid);
        perror(errmsg);

        close(epoll_fd);
        fclose(log_fp);
        close(server_fd);
        exit(1);
    }

    ev.events = EPOLLIN;
    ev.data.fd = server_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev) < 0) {
        sprintf(errmsg, "[%d] epoll_ctl() failed", connid);
        perror(errmsg);

        close(epoll_fd);
        fclose(log_fp);
        close(server_fd);
        exit(1);
    }

    while (true) {
        struct epoll_event e[2];
        int ne;
        if ((ne = epoll_wait(epoll_fd, e, 2, -1)) < 0) {
            sprintf(errmsg, "[%d] epoll_wait() failed", connid);
            perror(errmsg);
            break;
        }

        bool end_listen = false;

        char buf[4096];
        for (int i = 0; i < ne; i++) {
            int cfd = e[i].data.fd;
            if (cfd == client_fd) {
                ssize_t n = read(client_fd, buf, sizeof(buf));
                if (n <= 0) {
                    printf("[%d] read() failed on client\n", connid);
                    end_listen = true;
                    break;
                }
                up_bytes += n;
                ssize_t m = write(server_fd, buf, n);
                if (m != n) {
                    printf("[%d] write() failed on server\n", connid);
                    end_listen = true;
                    break;
                }
                fprintf(log_fp, ">>> %lu bytes\n", n);
                fwrite(buf, sizeof(char), n, log_fp);
                fputc('\n', log_fp);
            } else if (cfd == server_fd) {
                ssize_t n = read(server_fd, buf, sizeof(buf));
                if (n <= 0) {
                    printf("[%d] read() failed on server\n", connid);
                    end_listen = true;
                    break;
                }
                down_bytes += n;
                ssize_t m = write(client_fd, buf, n);
                if (m != n) {
                    printf("[%d] write() failed on client\n", connid);
                    end_listen = true;
                    break;
                }
                fprintf(log_fp, "<<< %lu bytes\n", n);
                fwrite(buf, sizeof(char), n, log_fp);
                fputc('\n', log_fp);
            }
        }

        if (end_listen) break;
    }

    printf("[%d] %s -> %s >>>%lu <<<%lu\n", connid, src_addr_str, dst_addr_str, up_bytes, down_bytes);

    close(epoll_fd);
    fclose(log_fp);
    close(server_fd);
    return 0;
}

int main(int argc, char **argv) {
    if (set_signal_handler() < 0) return 1;

    int listen_fd;
    struct sockaddr_in listen_addr;
    socklen_t listen_addr_len = sizeof(listen_addr);
    char listen_addr_str[32];
    int listen_port;
    int ret;

    if ((listen_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("socker() failed: %s\n", strerrordesc_np(errno)), ret = 1;
        goto FREE;
    }

    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    listen_addr.sin_port = htonl(0);
    if (bind(listen_fd, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
        perror("bind() failed"), ret = 1;
        goto FREE_LISTEN_FD;
    }

    if (listen(listen_fd, 16) < 0) {
        perror("listen() failed"), ret = 1;
        goto FREE_LISTEN_FD;
    }

    if (getsockname(listen_fd, (struct sockaddr *)&listen_addr, &listen_addr_len) < 0) {
        perror("getsockname() failed"), ret = 1;
        goto FREE_LISTEN_FD;
    }

    format_addr(&listen_addr, listen_addr_str, sizeof(listen_addr_str));
    printf("listen on %s\n", listen_addr_str);

    listen_port = ntohs(listen_addr.sin_port);

    if ((ret = setup_nftables(listen_port)) != 0) {
        printf("failed to setup nftables\n");
        goto FREE_NFTABLES;
    }

    while (!should_stop) {
        int client_fd;
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        struct sockaddr_in server_addr;
        socklen_t server_addr_len = sizeof(server_addr);
        pid_t pid;

        if ((client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &client_addr_len)) < 0) {
            perror("accept() failed");
            continue;
        }

        if (getsockopt(client_fd, SOL_IP, SO_ORIGINAL_DST, &server_addr, &server_addr_len)) {
            perror("getsockopt() failed");
            continue;
        }

        pid = fork();
        if (pid < 0) {
            perror("fork() failed");
            goto FREE_CLIENT_FD;
        }

        if (pid == 0) {
            close(listen_fd);
            handle_connection(client_fd, &client_addr, &server_addr);
            return 0;
        }

    FREE_CLIENT_FD:
        close(client_fd);
    }

FREE_NFTABLES:
    cleanup_nftables();
FREE_LISTEN_FD:
    close(listen_fd);
FREE:
    return ret;
}