#include "infector.h"
#include "targetopt.h"
#include "single.hpp"
#include "elfopt.h"
#include "log.h"

#include <sys/user.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

#define MAX_OPCODE_SIZE 30
#define CALL_RAX_CMD "\xff\xd0\xcc\x90\x90\x90\x90\x90"
#define JMP_CMD 0xe9

Infector::Infector(int pid_) :
    mPid(pid_)
{
    regvecInit();
    pNewRegs = static_cast<struct user_regs_struct *>(
               malloc(sizeof(struct user_regs_struct)));
    pOrigRegs = static_cast<struct user_regs_struct *>(
                malloc(sizeof(struct user_regs_struct)));
    pTargetOpt = new TargetOpt(pid_);
}

Infector::~Infector()
{
    free(pNewRegs);
    free(pOrigRegs);
    delete pTargetOpt;
    mRegvec.clear();
    Elf64Wrapper *pElf = TypeSingle<Elf64Wrapper>::getInstance();
    pElf->clearAllSyms();
}

void Infector::regvecInit()
{
    mRegvec.resize(7);
    mRegvec[0] = [this](long parm)
    {
        pNewRegs->rax = parm;
    };
    mRegvec[1] = [this](long parm)
    {
        pNewRegs->rdi = parm;
    };
    mRegvec[2] = [this](long parm)
    {
        pNewRegs->rsi = parm;
    };
    mRegvec[3] = [this](long parm)
    {
        pNewRegs->rdx = parm;
    };
    mRegvec[4] = [this](long parm)
    {
        pNewRegs->rcx = parm;
    };
    mRegvec[5] = [this](long parm)
    {
        pNewRegs->r8 = parm;
    };
    mRegvec[6] = [this](long parm)
    {
        pNewRegs->r9 = parm;
    };
}

bool Infector::backupTarget()
{
    if (!pTargetOpt->readTarget(*pOrigRegs))
        return false;

    if (!pTargetOpt->readTarget(pOrigRegs->rip, backupCode, sizeof(backupCode)))
        return false;

    memcpy(pNewRegs, pOrigRegs, sizeof(struct user_regs_struct));   
    return true; 
}

bool Infector::updateTarget()
{
    unsigned char newCode[8] = {0};
    newCode[0] = 0xff;
    newCode[1] = 0xd0;
    newCode[2] = 0xcc;
    memset(&newCode[3], 0x90, sizeof(newCode) - 3);

    if (!pTargetOpt->writeTarget(pNewRegs->rip, CALL_RAX_CMD, strlen(CALL_RAX_CMD)))
        return false;

    if (!pTargetOpt->writeTarget(*pNewRegs))
        return false;

    if (!pTargetOpt->contTarget())
        return false;
      
    int status;
    if (waitpid(mPid, &status, 0) < 0)
    {
        LOGGER_ERROR << "waitpid: " << strerror(errno);
        return false;
    }

    return true;
}

long Infector::restoreTarget()
{
    if (!pTargetOpt->readTarget(*pNewRegs))
        return 0;

    Elf64_Addr retAddr = pNewRegs->rax;

    if (!pTargetOpt->writeTarget(pOrigRegs->rip, backupCode, sizeof(backupCode)))
        return 0;

    if (!pTargetOpt->writeTarget(*pOrigRegs))
        return 0;

    return retAddr;
}

long Infector::getSym(const std::string &soname, const std::string &symname)
{
    Elf64Wrapper *pElf = TypeSingle<Elf64Wrapper>::getInstance();
    std::string soAllPath;
    Elf64_Addr baseAddr;
    if (!pTargetOpt->getTargetSoInfo(soname, soAllPath, baseAddr))
        return false;
    return pElf->getSym(soAllPath, symname);
}

bool Infector::loadSoFile(const std::string &soname)
{
    Elf64Wrapper *pElf = TypeSingle<Elf64Wrapper>::getInstance();
    std::string soAllPath;
    Elf64_Addr baseAddr;
    if (!pTargetOpt->getTargetSoInfo(soname, soAllPath, baseAddr))
        return false;
    return pElf->loadSo(soAllPath, baseAddr);
}

bool Infector::attachTarget()
{
    return pTargetOpt->attachTarget();
}

bool Infector::detachTarget()
{
    return pTargetOpt->detechTarget();
}

bool Infector::writeStrToTarget(Elf64_Addr &addr, const std::string &str)
{
    return pTargetOpt->writeTarget(addr, (void *)str.c_str(), str.size());
}

bool Infector::remoteFuncJump(Elf64_Addr &srcAddr, 
                              Elf64_Addr &dstAddr, 
                              Elf64_Addr &tmpAddr,
                              Elf64_Addr &setAddr)
{
    unsigned char origCode[MAX_OPCODE_SIZE] = {0};
    if (!pTargetOpt->readTarget(srcAddr, origCode, sizeof(origCode)))
        return false;

    if (!pTargetOpt->writeTarget(tmpAddr, origCode, sizeof(origCode)))
        return false;

    callRemoteFunc(setAddr, tmpAddr);

    unsigned char injectCode[8] = {0};
    injectCode[0] = JMP_CMD;
    int offset = dstAddr - srcAddr - 5;
    memcpy(&injectCode[1], &offset, 4);
    if (!pTargetOpt->writeTarget(srcAddr, injectCode, sizeof(injectCode)))
        return false;

    offset = srcAddr - tmpAddr - 5;
    memcpy(&injectCode[1], &offset, 4);
    if (!pTargetOpt->writeTarget(tmpAddr+12, injectCode, sizeof(injectCode)))
        return false;

    return true;
}