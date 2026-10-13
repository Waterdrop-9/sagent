/* fixture_190.c — CWE-190 整数溢出（真漏洞，ground truth）
 * 触发：连接 19000 端口，先发 4 字节长度 0xFFFFFFFC → len+4 回绕为 0 → malloc(0)，
 *       随后按 len 收数据写入堆缓冲 → 堆溢出。
 * 洞：unsigned int len 来自网络，len+4 加法未检查回绕，分配尺寸与复制尺寸不一致。
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
    addr.sin_port = htons(19000);
    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) return 1;
    if (listen(sfd, 4) < 0) return 1;

    for (;;) {
        int cfd = accept(sfd, NULL, NULL);
        if (cfd < 0) continue;
        unsigned int len = 0;
        ssize_t r = recv(cfd, &len, sizeof(len), 0);
        if (r != (ssize_t)sizeof(len)) { close(cfd); continue; }

        /* VULN: len+4 可能回绕，分配尺寸小于实际复制尺寸 */
        unsigned int total = len + 4;
        char *buf = (char *)malloc(total);
        if (!buf) { close(cfd); continue; }

        unsigned int got = 0;
        while (got < len) {
            ssize_t n = recv(cfd, buf + got, len - got, 0);
            if (n <= 0) break;
            got += (unsigned int)n;
        }
        free(buf);
        close(cfd);
    }
    return 0;
}
