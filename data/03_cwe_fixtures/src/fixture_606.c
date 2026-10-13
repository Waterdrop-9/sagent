/* fixture_606.c — CWE-606 未校验输入控制循环（真漏洞，ground truth）
 * 触发：连接 60600 端口，先发 4 字节计数 count（无上界检查，如 0x100），
 *       随后逐字节写 data[16] → count>16 时栈数组越界写。
 * 洞：循环边界直接来自网络输入，未校验上界，边界用作数组索引。
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
    addr.sin_port = htons(60600);
    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) return 1;
    if (listen(sfd, 4) < 0) return 1;

    char data[16];
    unsigned char byte;
    for (;;) {
        int cfd = accept(sfd, NULL, NULL);
        if (cfd < 0) continue;
        unsigned int count = 0;
        ssize_t r = recv(cfd, &count, sizeof(count), 0);
        if (r != (ssize_t)sizeof(count)) { close(cfd); continue; }

        /* VULN: count 无上界检查，直接作循环边界与数组索引 */
        unsigned int i;
        for (i = 0; i < count; i++) {
            ssize_t m = recv(cfd, &byte, 1, 0);
            if (m != 1) break;
            data[i] = (char)byte;
        }
        close(cfd);
    }
    return 0;
}
