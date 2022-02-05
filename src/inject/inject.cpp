#include "inject.h"

Inject *gInject = nullptr;
long Inject::syscallTable[100] = {0};

Inject::Inject()
{
    gInject = this;
}

void Inject::setAcceptAddr(long addr_)
{
    syscallTable[SystemCall::ACCEPT] = addr_;
}

ssize_t Inject::injectAccept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    long funAddr = syscallTable[SystemCall::ACCEPT];

    if (gInject)
        gInject->evilAccept(sockfd, addr, addrlen);
 
    if (funAddr)
            return ((typeof(injectAccept) *)funAddr)(sockfd, addr, addrlen);

    return 0;
}

ssize_t Inject::injectRead(int fd, void *buf, size_t count)
{
    long funAddr = syscallTable[SystemCall::READ];

    if (gInject)
        gInject->evilRead(fd, buf, count);

    if (funAddr)
        return ((typeof(injectRead) *)funAddr)(fd, buf, count);

    return 0;
}

void Inject::setReadAddr(long addr_)
{
    syscallTable[SystemCall::READ] = addr_;
}

ssize_t Inject::injectSend(int sockfd, const void *buf, size_t len, int flags)
{
    long funAddr = syscallTable[SystemCall::SEND];

    if (gInject)
        gInject->evilSend(sockfd, buf, len, flags);

    if (funAddr)
        return ((typeof(injectSend) *)funAddr)(sockfd, buf, len, flags);
 
    return 0;
}

void Inject::setSendAddr(long addr_)
{
    syscallTable[SystemCall::SEND] = addr_;
}

ssize_t Inject::injectWrite(int fd, const void *buf, size_t count)
{
    long funAddr = syscallTable[SystemCall::WRITE];

    if (gInject)
        gInject->evilWrite(fd, buf, count);
    
    if (funAddr)
        return ((typeof(injectWrite) *)funAddr)(fd, buf, count);

    return 0;
}

void Inject::setWriteAddr(long addr_)
{
    syscallTable[SystemCall::WRITE] = addr_;
}