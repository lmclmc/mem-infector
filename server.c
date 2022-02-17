//server端
#include<stdio.h>                                                                      
#include<stdlib.h>
#include<errno.h>
#include<string.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<netinet/in.h>
#include<arpa/inet.h>
void Usage(const char* proc)
{
    printf("%s [ip][port]\n");
}
int main(int argc,char* argv[])
{
    if(argc!=3){
        Usage(argv[0]);
        return 1;
    }
    int sock=socket(AF_INET,SOCK_DGRAM,0);
    if(sock<0){
        perror("socket");
        return 2;
    }
    int _port=atoi(argv[2]);
    char* _ip=argv[1];
    struct sockaddr_in local;
    local.sin_family=AF_INET;
    local.sin_port=htons(_port);
    local.sin_addr.s_addr=inet_addr(_ip);
    if(bind(sock,(struct sockaddr*)&local,sizeof(local))<0){
        perror("bind");
        exit(1);
    }
    char buf[1024];
    struct sockaddr_in remote;
    socklen_t len=sizeof(remote);
    while(1)
    {
        ssize_t _s=recvfrom(sock,buf,sizeof(buf)-1,0,(struct sockaddr*)&remote,&len);
        if(_s>0)
        {
            buf[_s]='\0';
            printf("%s", buf);
	}
         else if(_s==0){
            printf("client close");
            break;
        }
        else
        {
            break;
        }
 
    }
    close(sock);
    return 0;
}
//client端
