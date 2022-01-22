#include <stdio.h>

#include <netinet/in.h>
#include <arpa/inet.h>

static long addr = 0;
static long acceptAddr = 0;

int setAddr(long addr_)
{
        addr = addr_;
        return 111;
}

ssize_t injectRecvFrom(int sockfd, void *buf, size_t len, int flags, long a1, long a2)
{
    char buffer[256] = {0};
    if (addr)
    {
            int ret = ((typeof(injectRecvFrom) *)addr)(sockfd, buf, len, flags, a1, a2);
            sprintf(buffer, "echo \"%s\" >> /home/lmc/Desktop/zzz", buf);
            system(buffer);
            return ret;
    }

    return 0;
}

int setAcceptAddr(long addr_)
{
        acceptAddr = addr_;
         printf("wwwwwwwwwwwwwwwwwwwwww\n");
        return 111;
}

ssize_t injectAccept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    char buffer[256] = {0};
    printf("111111111112211111111111111\n");
    char buf[64] = {0};
    
    if (acceptAddr)
    {
            int ret = ((typeof(injectAccept) *)acceptAddr)(sockfd, addr, addrlen);
            struct sockaddr_in *addrClient = addr; 
             struct sockaddr_in6 *their_addr = addr; 
             char *a = inet_ntop(AF_INET6, (const void *)&their_addr->sin6_addr, buf, sizeof(buf));
            sprintf(buffer, "echo \"%s:%d\" >> /home/lmc/Desktop/zzz", buf, ntohs(addrClient->sin_port));
            system(buffer);
            return ret;
    }

    return 0;
}

int whileasd()
{
        while (1)
        {
           //     printf("vfer\n");
        }
}

