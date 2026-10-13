/* fixture_416.c — CWE-416 Use-After-Free（真漏洞，ground truth）
 * 触发：连接 41600 端口，发送任意数据：先收数据进 p，free(p) 后再次 send(p, ...)
 *       → 释放后读取堆内存。
 * 洞：同一可达路径上，free 之后对同一指针解引用（send 读内存）。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void)
{
    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) return 1;
    int one = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(41600);
    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) return 1;
    if (listen(sfd, 4) < 0) return 1;

    for (;;) {
        int cfd = accept(sfd, NULL, NULL);
        if (cfd < 0) continue;

        char *p = (char *)malloc(256);
        if (!p) { close(cfd); continue; }
        ssize_t n = recv(cfd, p, 255, 0);
        if (n <= 0) { free(p); close(cfd); continue; }
        p[n] = '\0';

        free(p);                     /* 释放 */
        /* VULN: 释放后仍从 p 读取并发送 —— use-after-free */
        send(cfd, p, (size_t)n, 0);
        close(cfd);
    }
    return 0;
}
