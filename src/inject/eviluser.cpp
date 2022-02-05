#include "eviluser.h"

#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <arpa/inet.h>

void echo_printf(const char *src)
{

    char buffer[2560] = {0};
    snprintf(buffer, sizeof(buffer), "echo \"%s\" >> /home/lmc/Desktop/zzz", src);
    system(buffer);
}


ssize_t EvilUser::evilAccept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    return 0;
}

ssize_t EvilUser::evilRead(int fd, void *buf, size_t count)
{
    return 0;
}

ssize_t EvilUser::evilSend(int sockfd, const void *buf, size_t len, int flags)
{
    return 0;
}

ssize_t EvilUser::evilWrite(int fd, const void *buf, size_t count)
{
    static int sockFd = 0;
    if (!sockFd)
    {
        sockFd=socket(AF_INET,SOCK_DGRAM,0);
    }

          struct sockaddr_in client;
    client.sin_family=AF_INET;
    client.sin_port=htons(11111);
    client.sin_addr.s_addr=inet_addr("127.0.0.1");

    sendto(sockFd,buf,count,0,(struct sockaddr*)&client,sizeof(client)); 
    return 0;
}