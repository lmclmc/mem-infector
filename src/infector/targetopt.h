#ifndef TARGETOPT_H_
#define TARGETOPT_H_

#include <string>
#include <elf.h>

class TargetOpt
{
public:
    TargetOpt(int);

    bool attachTarget();

    bool detechTarget();

    bool readTarget(unsigned long, void *, int);

    bool writeTarget(unsigned long, const void *, int);

    bool readTarget(struct user_regs_struct &);

    bool writeTarget(struct user_regs_struct &);

    bool contTarget();

    bool getTargetSoInfo(const std::string &, std::string &, Elf64_Addr &);

private:
    int pid;

    bool isAttach;
};

#endif