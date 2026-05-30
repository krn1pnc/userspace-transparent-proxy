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

static volatile sig_atomic_t should_stop = 0;

void signal_handler_stop(int signum) { should_stop = 1; }

const char *LOG_DIR = "./log";

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
    int connid = rand();
    char errmsg[64];

    char src_addr_str[64], dst_addr_str[64];
    format_addr(src_addr, src_addr_str, sizeof(src_addr_str));
    format_addr(dst_addr, dst_addr_str, sizeof(dst_addr_str));
    printf("[%d] New connection: %s -> %s\n", connid, src_addr_str, dst_addr_str);

    int server_fd;
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        sprintf(errmsg, "[%d] socket() failed", connid);
        perror(errmsg);

        exit(1);
    }

    int direct_mark = 0x0416;
    if (setsockopt(server_fd, SOL_SOCKET, SO_MARK, &direct_mark, sizeof(direct_mark)) < 0) {
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

    char filename[256];
    sprintf(filename, "%s/%d_%s_to_%s.log", LOG_DIR, connid, src_addr_str, dst_addr_str);

    mkdir(LOG_DIR, 0755);
    FILE *log_file = fopen(filename, "wb");
    if (!log_file) {
        sprintf(errmsg, "[%d] fopen() failed", connid);
        perror(errmsg);

        close(server_fd);
        exit(1);
    }

    int epoll_fd;
    if ((epoll_fd = epoll_create1(0)) < 0) {
        sprintf(errmsg, "[%d] epoll_create1() failed", connid);
        perror(errmsg);

        fclose(log_file);
        close(server_fd);
        exit(1);
    }

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = client_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev) < 0) {
        sprintf(errmsg, "[%d], epoll_ctl() failed", connid);
        perror(errmsg);

        close(epoll_fd);
        fclose(log_file);
        close(server_fd);
        exit(1);
    }

    ev.events = EPOLLIN;
    ev.data.fd = server_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev) < 0) {
        sprintf(errmsg, "[%d] epoll_ctl() failed", connid);
        perror(errmsg);

        close(epoll_fd);
        fclose(log_file);
        close(server_fd);
        exit(1);
    }

    ssize_t up_bytes = 0, down_bytes = 0;
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
                fprintf(log_file, ">>> %lu bytes\n", n);
                fwrite(buf, sizeof(char), n, log_file);
                fputc('\n', log_file);
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
                fprintf(log_file, "<<< %lu bytes\n", n);
                fwrite(buf, sizeof(char), n, log_file);
                fputc('\n', log_file);
            }
        }

        if (end_listen) break;
    }

    printf("[%d] %s -> %s >>>%lu <<<%lu\n", connid, src_addr_str, dst_addr_str, up_bytes, down_bytes);

    close(epoll_fd);
    fclose(log_file);
    close(server_fd);
    return 0;
}

int main(int argc, char **argv) {
    struct sigaction sa;
    sa.sa_handler = signal_handler_stop;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGINT, &sa, NULL) < 0 || sigaction(SIGTERM, &sa, NULL) < 0) {
        perror("sigaction failed");
        return -1;
    }

    int listen_fd;
    if ((listen_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket() failed");
        return 1;
    }

    struct sockaddr_in listen_addr;
    socklen_t listen_addr_len = sizeof(listen_addr);

    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    listen_addr.sin_port = htonl(0);
    if (bind(listen_fd, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
        perror("bind() failed");
        close(listen_fd);
        return 1;
    }

    if (listen(listen_fd, 16) < 0) {
        perror("listen() failed");
        close(listen_fd);
        return 1;
    }

    if (getsockname(listen_fd, (struct sockaddr *)&listen_addr, &listen_addr_len) < 0) {
        perror("getsockname() failed");
        close(listen_fd);
        return 1;
    }

    char listen_addr_str[32];
    format_addr(&listen_addr, listen_addr_str, sizeof(listen_addr_str));
    printf("listen on %s\n", listen_addr_str);

    int listen_port = ntohs(listen_addr.sin_port);

    int ret;
    if ((ret = setup_nftables(listen_port)) != 0) {
        printf("failed to setup nftables\n");
        cleanup_nftables();
        close(listen_fd);
        return ret;
    }

    while (!should_stop) {
        int client_fd;
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        if ((client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &client_addr_len)) < 0) {
            perror("accept() failed");
            continue;
        }

        struct sockaddr_in orig_dst;
        socklen_t orig_dst_len = sizeof(orig_dst);
        if (getsockopt(client_fd, SOL_IP, SO_ORIGINAL_DST, &orig_dst, &orig_dst_len)) {
            perror("getsockopt() failed");
            continue;
        }

        pid_t pid = fork();
        if (pid < 0) {
            perror("fork() failed");
            close(client_fd);
            continue;
        }
        if (pid == 0) {
            close(listen_fd);
            handle_connection(client_fd, &client_addr, &orig_dst);
            return 0;
        } else {
            close(client_fd);
        }
    }

    cleanup_nftables();
    close(listen_fd);
    return 0;
}