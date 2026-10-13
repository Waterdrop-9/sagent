/* fixture_134.c — CWE-134 未校验格式字符串（真漏洞，ground truth）
 * 触发：连接 13400 端口，发送任意含 %x/%n 的字符串 → printf(buf) 直接当作格式串解析。
 * 洞：recv 数据未经清洗作为 printf 的格式参数。
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
    addr.sin_port = htons(13400);
    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) return 1;
    if (listen(sfd, 4) < 0) return 1;

    char buf[256];
    for (;;) {
        int cfd = accept(sfd, NULL, NULL);
        if (cfd < 0) continue;
        ssize_t n = recv(cfd, buf, sizeof(buf) - 1, 0);
        if (n > 0) {
            buf[n] = '\0';
            /* VULN: 网络输入直接作为格式字符串 */
            printf(buf);
            fflush(stdout);
        }
        close(cfd);
    }
    return 0;
}
