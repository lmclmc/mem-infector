#ifndef INJECT_H_
#define INJECT_H_

#include <stdio.h>
#include <sys/socket.h>

#define EXPORT_INJECT(type) \
    type g##type;

typedef enum classSystemCall_ : unsigned char
{
    ACCEPT = 0,
    READ = 1,
    SEND = 2,
    WRITE = 3
}SystemCall;

class Inject
{
public:
    Inject();

protected:
    virtual ssize_t evilAccept(int, struct sockaddr *, socklen_t *) = 0;
    virtual ssize_t evilRead(int fd, void *buf, size_t count) = 0;
    virtual ssize_t evilSend(int sockfd, const void *buf, size_t len, int flags) = 0;
    virtual ssize_t evilWrite(int fd, const void *buf, size_t count) = 0;

private:
    static ssize_t injectAccept(int, struct sockaddr *, socklen_t *);
    void setAcceptAddr(long);

    static ssize_t injectRead(int fd, void *buf, size_t count); 
    void setReadAddr(long);

    static ssize_t injectSend(int sockfd, const void *buf, size_t len, int flags);
    void setSendAddr(long);

    static ssize_t injectWrite(int fd, const void *buf, size_t count);
    void setWriteAddr(long);
private:
    static long syscallTable[100];
};

void echo_printf(const char *src);

#endif