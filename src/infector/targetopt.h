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

    bool stepTarget();

    bool getTargetSoInfo(const std::string &, std::string &, Elf64_Addr &);

    bool getHeapInfo(Elf64_Addr &, long &);

    bool getStackInfo(Elf64_Addr &, long &);

private:
    bool readTargetMaps(const std::string &,std::string &, Elf64_Addr &, long &);

private:
    int pid;

    bool isAttach;
};

#endif