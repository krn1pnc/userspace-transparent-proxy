#define _GNU_SOURCE

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define BUF_SIZE 128
#define HASH_BUCKET_SIZE 65536
#define LRU_EXPIRE_AFTER (5 * 60)
#define MAX_EVENTS 512
#define UDP_PACKET_MAX_SIZE 65536

const char *LOG_DIR = "./log";
const int ENABLE = 1;
const int DIRECT_MARK = 0x0721;

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

struct list_node {
    struct list_node *pre, *nxt;
    void *data;
};

// insert n after p
void list_insert(struct list_node *p, struct list_node *n) {
    n->nxt = p->nxt;
    if (p->nxt) p->nxt->pre = n;
    n->pre = p, p->nxt = n;
}

// remove p from the list. caller should free p
void list_delete(struct list_node *p) {
    if (p->nxt) p->nxt->pre = p->pre;
    if (p->pre) p->pre->nxt = p->nxt;
}

struct hash_key {
    uint32_t c_addr, s_addr;
    uint16_t c_port, s_port;
};

bool hash_key_eq(const struct hash_key *a, const struct hash_key *b) {
    return !memcmp(a, b, sizeof(struct hash_key));
}

struct hash_pkv {
    struct hash_key k;
    struct list_node *v;
};

struct list_node *hashmap_head[HASH_BUCKET_SIZE];

uint64_t xorshift64(uint64_t x) {
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    return x;
}

size_t hash(const struct hash_key *k) {
    uint64_t h = 0;
    h = xorshift64(h ^ ((uint64_t)k->c_port << 32 | k->c_addr));
    h = xorshift64(h ^ ((uint64_t)k->s_port << 32 | k->s_addr));
    return h % HASH_BUCKET_SIZE;
}

struct list_node *hashmap_get_node(struct list_node *head, const struct hash_key *k) {
    for (struct list_node *p = head; p; p = p->nxt) {
        if (hash_key_eq(k, &((struct hash_pkv *)p->data)->k)) return p;
    }
    return NULL;
}

// return old value when replace
struct list_node *hashmap_set(const struct hash_key *k, struct list_node *v) {
    size_t h = hash(k);
    struct list_node *p = hashmap_get_node(hashmap_head[h], k);
    if (p) {
        struct list_node *old_v = ((struct hash_pkv *)p->data)->v;
        ((struct hash_pkv *)p->data)->v = v;
        return old_v;
    } else {
        struct hash_pkv *pkv = malloc(sizeof(struct hash_pkv));
        memset(pkv, 0, sizeof(struct hash_pkv));
        pkv->k = *k, pkv->v = v;
        p = malloc(sizeof(struct list_node));
        memset(p, 0, sizeof(struct list_node));
        p->data = (void *)pkv;
        if (!hashmap_head[h]) hashmap_head[h] = p;
        else list_insert(p, hashmap_head[h]), hashmap_head[h] = p;
        return NULL;
    }
}

struct list_node *hashmap_delete(const struct hash_key *k) {
    size_t h = hash(k);
    struct list_node *p = hashmap_get_node(hashmap_head[h], k);

    if (!p) return NULL;

    struct hash_pkv *pkv = (struct hash_pkv *)p->data;
    struct list_node *v = pkv->v;
    free(pkv);

    list_delete(p);
    if (p == hashmap_head[h]) hashmap_head[h] = p->nxt;
    free(p);

    return v;
}

struct list_node *hashmap_get(const struct hash_key *k) {
    size_t h = hash(k);
    struct list_node *p = hashmap_get_node(hashmap_head[h], k);
    return p ? ((struct hash_pkv *)p->data)->v : NULL;
}

struct udp_conn {
    int up_fd;   // read & write
    int down_fd; // write only
};

struct lru_item {
    time_t last_active;
    struct udp_conn *data;
    struct hash_key k;
};

struct list_node lru_list;

void lru_init() { lru_list.nxt = lru_list.pre = &lru_list; }

struct udp_conn *lru_get(struct hash_key *k) {
    struct list_node *p = hashmap_get(k);
    return p ? ((struct lru_item *)p->data)->data : NULL;
}

void lru_set(const struct hash_key *k, struct udp_conn *v) {
    struct lru_item *it = malloc(sizeof(struct lru_item));
    memset(it, 0, sizeof(struct lru_item));
    it->last_active = time(NULL), it->data = v, it->k = *k;

    struct list_node *p = malloc(sizeof(struct list_node));
    memset(p, 0, sizeof(struct list_node));
    p->data = (void *)it;

    list_insert(&lru_list, p);
    struct list_node *old_p = hashmap_set(k, p);
    assert(!old_p);
}

int lru_touch(struct hash_key *k) {
    struct list_node *p = hashmap_get(k);
    assert(p);

    list_delete(p);
    ((struct lru_item *)p->data)->last_active = time(NULL);
    list_insert(&lru_list, p);
    return 0;
}

void lru_remove_expired(void (*cb)(struct udp_conn *v)) {
    time_t now = time(NULL);
    struct list_node *p = lru_list.pre;
    while (p != &lru_list && now - ((struct lru_item *)p->data)->last_active > LRU_EXPIRE_AFTER) {
        struct lru_item *it = p->data;
        cb(it->data); // released
        hashmap_delete(&it->k);
        free(it);

        struct list_node *nxt = p->pre;
        list_delete(p);
        free(p);
        p = nxt;
    }
}

static volatile sig_atomic_t should_stop = 0;
void signal_handler_stop(int signum) { should_stop = 1; }
int setup_signal_handler() {
    struct sigaction sa;
    sa.sa_flags = 0;
    sa.sa_handler = signal_handler_stop;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) < 0 || sigaction(SIGTERM, &sa, NULL) < 0) {
        log_error_info("sigaction() failed");
        return -1;
    }
    return 0;
}

bool _nftable_created, _ip_rule_set, _ip_route_set;
int setup_tproxy(int listen_port) {
    if (system("nft add table ip ebifurai")) return -1;
    _nftable_created = true;
    if (system("nft 'add chain ip ebifurai output { type route hook output priority mangle; policy accept; }'") != 0) return -1;
    if (system("nft add rule ip ebifurai output meta mark 0x00000721 counter return") != 0) return -1;
    if (system("nft add rule ip ebifurai output meta l4proto udp counter meta mark set 0x00000722") != 0) return -1;
    if (system("nft 'add chain ip ebifurai prerouting { type filter hook prerouting priority mangle; policy accept; }'") != 0) return -1;
    char cmd[128];
    sprintf(cmd, "nft add rule ip ebifurai prerouting meta mark 0x00000722 meta l4proto udp counter tproxy to 127.0.0.1:%d", listen_port);
    if (system(cmd) != 0) return -1;

    if (system("ip rule add fwmark 0x00000722 table 147 priority 727") != 0) return -1;
    _ip_rule_set = true;
    if (system("ip route add local 0.0.0.0/0 dev lo table 147") != 0) return -1;
    _ip_route_set = true;
    return 0;
}

void cleanup_tproxy() {
    if (_nftable_created) system("nft delete table ip ebifurai");
    if (_ip_rule_set) system("ip rule del priority 727");
    if (_ip_route_set) system("ip route flush table 147");
}

int epoll_fd;

void free_udp_conn(struct udp_conn *c) {
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, c->up_fd, NULL);
    close(c->up_fd);
    close(c->down_fd);
    free(c);
}

void handle_client_packet(int listen_fd) {
    struct cmsghdr *cmsg;
    char data[UDP_PACKET_MAX_SIZE];
    char cmsg_data[CMSG_SPACE(sizeof(struct sockaddr_in))];

    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    struct sockaddr_in server_addr;
    socklen_t server_addr_len = sizeof(server_addr);
    char server_addr_str[BUF_SIZE];

    ssize_t n, m;
    struct udp_conn *c;
    char log_filename[BUF_SIZE];

    FILE *log_fp = NULL;

    struct iovec iov = {.iov_base = data, .iov_len = sizeof(data)};
    struct msghdr msg = {
        .msg_name = &client_addr,
        .msg_namelen = client_addr_len,
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cmsg_data,
        .msg_controllen = sizeof(cmsg_data),
    };

    n = recvmsg(listen_fd, &msg, 0);
    if (n < 0) {
        log_error_info("recvmsg() failed");
        goto EXIT;
    }

    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_ORIGDSTADDR) {
            memcpy(&server_addr, CMSG_DATA(cmsg), sizeof(struct sockaddr_in));
            break;
        }
    }

    format_addr(&server_addr, server_addr_str, sizeof(server_addr_str));
    if (mkdir(LOG_DIR, 0755) < 0) {
        if (errno != EEXIST) log_error_info("mkdir() failed");
    }
    sprintf(log_filename, "%s/%ld_%s_up", LOG_DIR, time(NULL), server_addr_str);
    log_info("send %zu bytes to %s, saving to %s", n, server_addr_str, log_filename);
    log_fp = fopen(log_filename, "wb");
    if (!log_fp) log_error_info("fopen() failed");

    if (log_fp) fwrite(data, sizeof(char), n, log_fp);

    struct hash_key k = {
        .c_addr = client_addr.sin_addr.s_addr,
        .c_port = client_addr.sin_port,
        .s_addr = server_addr.sin_addr.s_addr,
        .s_port = server_addr.sin_port,
    };

    c = lru_get(&k);
    if (c) {
        lru_touch(&k);
        iov.iov_base = data;
        iov.iov_len = n;

        msg.msg_name = NULL;
        msg.msg_namelen = 0;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = NULL;
        msg.msg_controllen = 0;

        m = sendmsg(c->up_fd, &msg, 0);
        if (m < 0) log_error_info("up sendmsg() failed");
        else if (m != n) log_error("sent %zu bytes but except %zu bytes", m, n);
    } else {
        struct epoll_event ev;

        c = malloc(sizeof(struct udp_conn));
        memset(c, 0, sizeof(struct udp_conn));

        c->up_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (c->up_fd < 0) {
            log_error_info("up socket() failed");
            goto ERROR_C;
        }
        if (setsockopt(c->up_fd, SOL_SOCKET, SO_MARK, &DIRECT_MARK, sizeof(DIRECT_MARK)) < 0) {
            log_error_info("up setsockopt(SO_MARK) failed");
            goto ERROR_UP_FD;
        }
        if (connect(c->up_fd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            log_error_info("up connect() failed");
            goto ERROR_UP_FD;
        }

        c->down_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (c->down_fd < 0) {
            log_error_info("down socket() failed");
            goto ERROR_UP_FD;
        }
        if (setsockopt(c->down_fd, SOL_SOCKET, SO_MARK, &DIRECT_MARK, sizeof(DIRECT_MARK)) < 0) {
            log_error_info("down setsockopt(SO_MARK) failed");
            goto ERROR_DOWN_FD;
        }
        if (setsockopt(c->down_fd, SOL_SOCKET, SO_REUSEADDR, &ENABLE, sizeof(ENABLE)) < 0) {
            log_error_info("down setsockopt(SO_REUSEADDR) failed");
            goto ERROR_DOWN_FD;
        }
        if (setsockopt(c->down_fd, SOL_IP, IP_TRANSPARENT, &ENABLE, sizeof(ENABLE)) < 0) {
            log_error_info("down setsockopt(IP_TRANSPARENT) failed");
            goto ERROR_DOWN_FD;
        }
        if (bind(c->down_fd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            log_error_info("down bind() failed");
            goto ERROR_DOWN_FD;
        }
        if (connect(c->down_fd, (const struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
            log_error_info("down connect() failed");
            goto ERROR_DOWN_FD;
        }

        memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLIN;
        ev.data.fd = c->up_fd;
        ev.data.ptr = c;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, c->up_fd, &ev) < 0) {
            log_error_info("up epollctl() failed");
            goto ERROR_DOWN_FD;
        }

        lru_set(&k, c);

        iov.iov_base = data;
        iov.iov_len = n;

        msg.msg_name = NULL;
        msg.msg_namelen = 0;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = NULL;
        msg.msg_controllen = 0;

        m = sendmsg(c->up_fd, &msg, 0);
        if (m < 0) log_error_info("up sendmsg() failed");
        else if (m != n) log_error("sent %zu bytes but except %zu bytes", m, n);

        goto EXIT;

    ERROR_DOWN_FD:
        close(c->down_fd);
    ERROR_UP_FD:
        close(c->up_fd);
    ERROR_C:
        free(c);
    }

EXIT:
    if (log_fp) fclose(log_fp);
    return;
}

void handle_server_packet(const struct udp_conn *c) {
    char data[UDP_PACKET_MAX_SIZE];
    struct sockaddr_in server_addr;
    socklen_t server_addr_len = sizeof(server_addr);
    char log_filename[BUF_SIZE], server_addr_str[BUF_SIZE];
    struct iovec iov = {.iov_base = data, .iov_len = sizeof(data)};
    struct msghdr msg = {
        .msg_name = &server_addr,
        .msg_namelen = server_addr_len,
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = NULL,
        .msg_controllen = 0,
    };
    ssize_t n, m;
    FILE *log_fp = NULL;

    n = recvmsg(c->up_fd, &msg, 0);
    if (n < 0) {
        log_error_info("up recvmsg() failed");
        goto EXIT;
    }

    format_addr(&server_addr, server_addr_str, sizeof(server_addr_str));
    if (mkdir(LOG_DIR, 0755) < 0) {
        if (errno != EEXIST) log_error_info("mkdir() failed");
    }
    sprintf(log_filename, "%s/%ld_%s_down", LOG_DIR, time(NULL), server_addr_str);
    log_info("recv %zu bytes from %s, saving to %s", n, server_addr_str, log_filename);
    log_fp = fopen(log_filename, "wb");
    if (!log_fp) log_error_info("fopen() failed");

    if (log_fp) fwrite(data, sizeof(char), n, log_fp);

    iov.iov_base = data;
    iov.iov_len = n;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;

    m = sendmsg(c->down_fd, &msg, 0);
    if (m < 0) log_error_info("up sendmsg() failed");
    else if (m != n) log_error("sent %zu bytes but except %zu bytes", m, n);

EXIT:
    if (log_fp) fclose(log_fp);
    return;
}

int main(int argc, char **argv) {
    if (setup_signal_handler() < 0) return 0;

    int listen_fd;
    struct sockaddr_in listen_addr;
    socklen_t listen_addr_len = sizeof(listen_addr);
    char listen_addr_str[BUF_SIZE];
    int listen_port;
    struct epoll_event ev;

    listen_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (listen_fd < 0) {
        log_error_info("listen() failed");
        goto EXIT;
    }
    if (setsockopt(listen_fd, IPPROTO_IP, IP_TRANSPARENT, &ENABLE, sizeof(ENABLE)) < 0) {
        log_error_info("setsockopt(IP_TRANSPARENT) failed");
        goto EXIT_LISTEN_FD;
    }
    if (setsockopt(listen_fd, IPPROTO_IP, IP_RECVORIGDSTADDR, &ENABLE, sizeof(ENABLE)) < 0) {
        log_error_info("setsockopt(IP_RECVORIGDSTADDR) failed");
        goto EXIT_LISTEN_FD;
    }

    memset(&listen_addr, 0, listen_addr_len);
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    listen_addr.sin_port = htons(0);
    if (bind(listen_fd, (struct sockaddr *)&listen_addr, listen_addr_len) < 0) {
        log_error_info("bind() failed");
        goto EXIT_LISTEN_FD;
    }

    if (getsockname(listen_fd, (struct sockaddr *)&listen_addr, &listen_addr_len) < 0) {
        log_error_info("getsockname() failed");
        goto EXIT_LISTEN_FD;
    }

    format_addr(&listen_addr, listen_addr_str, listen_addr_len);
    log_info("listen on %s", listen_addr_str);

    listen_port = ntohs(listen_addr.sin_port);

    if (setup_tproxy(listen_port) < 0) {
        log_error("failed to set up tproxy");
        goto EXIT_TPROXY;
    }

    epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        log_error_info("epoll_create1() failed");
        goto EXIT_TPROXY;
    }

    memset(&ev, 0, sizeof(struct epoll_event));

    ev.events = EPOLLIN;
    ev.data.fd = listen_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &ev) < 0) {
        log_error_info("epoll_ctl() failed");
        goto EXIT_EPOLL_FD;
    }

    lru_init();

    while (!should_stop) {
        struct epoll_event e[MAX_EVENTS];
        int ne;

        ne = epoll_wait(epoll_fd, e, MAX_EVENTS, -1);
        if (ne < 0) {
            log_error_info("epoll_wait() failed");
            goto EXIT_EPOLL;
        }

        for (int i = 0; i < ne; i++) {
            if (e[i].data.fd == listen_fd) handle_client_packet(listen_fd);
            else handle_server_packet((struct udp_conn *)e[i].data.ptr);
        }

        lru_remove_expired(free_udp_conn);

        continue;
    EXIT_EPOLL:
        break;
    }

EXIT_EPOLL_FD:
    close(epoll_fd);
EXIT_TPROXY:
    cleanup_tproxy();
EXIT_LISTEN_FD:
    close(listen_fd);
EXIT:
    exit(0);
}