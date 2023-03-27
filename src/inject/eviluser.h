#ifndef EVILUSER_H_
#define EVILUSER_H_

#include "inject/inject.h"

#include <stdio.h>

class EvilUser final : public Inject
{
public:
    EvilUser();
    ~EvilUser();

protected:
    ssize_t evilAccept(int, struct sockaddr *, socklen_t *) override;
    ssize_t evilRead(int, void *, size_t) override;
    ssize_t evilSend(int, const void *, size_t, int) override;
    ssize_t evilWrite(int, const void *, size_t) override;
    void evilMain() override;

private:
    char *tmpBuffer;
};

void echo_printf(const char *src);

EXPORT_INJECT(EvilUser)


#endif