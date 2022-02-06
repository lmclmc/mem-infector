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
    virtual ~Inject();

protected:
    virtual ssize_t evilAccept(int, struct sockaddr *, socklen_t *) = 0;
    virtual ssize_t evilRead(int, void *&, size_t &) = 0;
    virtual ssize_t evilSend(int, const void *&, size_t &, int) = 0;
    virtual ssize_t evilWrite(int, const void *&, size_t &) = 0;

private:
    static ssize_t injectAccept(int, struct sockaddr *, socklen_t *);
    void setAcceptAddr(long);

    static ssize_t injectRead(int, void *, size_t); 
    void setReadAddr(long);

    static ssize_t injectSend(int, const void *, size_t, int);
    void setSendAddr(long);

    static ssize_t injectWrite(int, const void *, size_t);
    void setWriteAddr(long);
private:
    static long syscallTable[100];
};

void echo_printf(const char *src);

#endif