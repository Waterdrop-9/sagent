/* fixture_415.c — CWE-415 Double Free（真漏洞，ground truth）
 * 触发：连接 41500 端口，发送任意以 'x' 开头的数据：
 *       错误路径先 free(p)，随后无条件 free(p) → 同一对象两次释放。
 * 洞：网络输入控制错误分支，两个 free 在同一可达路径上。
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
    addr.sin_port = htons(41500);
    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) return 1;
    if (listen(sfd, 4) < 0) return 1;

    char cmd[64];
    for (;;) {
        int cfd = accept(sfd, NULL, NULL);
        if (cfd < 0) continue;
        ssize_t n = recv(cfd, cmd, sizeof(cmd) - 1, 0);
        if (n <= 0) { close(cfd); continue; }
        cmd[n] = '\0';

        char *p = (char *)malloc(128);
        if (!p) { close(cfd); continue; }

        if (cmd[0] == 'x') {
            /* 错误路径 */
            free(p);                 /* 第一次释放 */
            close(cfd);
            /* VULN: 无条件释放同一对象 —— 与上面的 free 构成 double free */
        }
        free(p);                     /* 第二次释放（同一对象） */
        close(cfd);
    }
    return 0;
}
