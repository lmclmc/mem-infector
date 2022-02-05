#ifndef EVILUSER_H_
#define EVILUSER_H_

#include "inject/inject.h"

#include <stdio.h>

class EvilUser final : public Inject
{

protected:
    ssize_t evilAccept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) override;
    ssize_t evilRead(int fd, void *buf, size_t count) override;
    ssize_t evilSend(int sockfd, const void *buf, size_t len, int flags) override;
    ssize_t evilWrite(int fd, const void *buf, size_t count) override;
};

EXPORT_INJECT(EvilUser)

#endif