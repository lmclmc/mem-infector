#include "infector.h"
#include "targetopt.h"
#include "single.hpp"
#include "elfopt.h"
#include "log.h"
extern "C"
{
#include "xed/xed-interface.h"
}

#include <assert.h>
#include <sys/user.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>

#define MAX_OPCODE_SIZE 30
#define JMP_SIZE 5
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

    xedd = static_cast<xed_decoded_inst_t *>(
               malloc(sizeof(xed_decoded_inst_t)));

    xed_tables_init();

    xed_state_t dstate;
    dstate.mmode=XED_MACHINE_MODE_LONG_64;
    xed_decoded_inst_zero_set_mode(xedd, &dstate);
}

Infector::~Infector()
{
    free(pNewRegs);
    free(pOrigRegs);
    delete pTargetOpt;
    mRegvec.clear();
    Elf64Wrapper *pElf = TypeSingle<Elf64Wrapper>::getInstance();
    pElf->clearAllSyms();
    free(xedd);
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

bool Infector::stepTarget()
{
    return pTargetOpt->stepTarget();
}

long Infector::getSym(const std::string &soname, const std::string &symname)
{
    Elf64Wrapper *pElf = TypeSingle<Elf64Wrapper>::getInstance();
    std::string soAllPath;
    Elf64_Addr baseAddr;

    auto it = soMap.find(soname);
    if (it == soMap.end())
    {
        if (!pTargetOpt->getTargetSoInfo(soname, soAllPath, baseAddr))
            return false;

         soMap.insert(std::pair<std::string, std::string>(soname, soAllPath));
         it = soMap.find(soname);
    }
    
    return pElf->getSym(it->second, symname);
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

Elf64_Addr Infector::syscallJmp(const std::string &syscall, 
                                const std::string &injectCall, 
                                const std::string &setSyscall, 
                                Elf64_Addr tmpAddr)
{
    Elf64_Addr syscallAddr = getSym("libc-2.31.so", syscall);
    Elf64_Addr injectCallAddr = getSym("libinject.so", injectCall);
    Elf64_Addr setSyscallAddr = getSym("libinject.so", setSyscall);

    int offset = remoteFuncJump(syscallAddr, injectCallAddr, 
                                tmpAddr, setSyscallAddr);

    if (offset < 0) return 0;

    return tmpAddr + offset;
}

bool Infector::injectSysTableInit()
{
    Elf64_Addr mmapAddr = getSym("libc-2.31.so", "mmap");

    if (!loadSoFile("libinject.so"))
    {
        printf("=== %s, %d\n", __func__, __LINE__);
        return false;
    }

    Elf64_Addr mmapRetAddr = callRemoteFunc(mmapAddr, 0, 4096, 
                                PROT_READ | PROT_WRITE | PROT_EXEC, 
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(mmapRetAddr);

    mmapRetAddr = syscallJmp("accept", "_ZN6Inject12injectAcceptEiP8sockaddrPj", 
                             "_ZN6Inject13setAcceptAddrEl", mmapRetAddr);
    assert(mmapRetAddr);

    mmapRetAddr = syscallJmp("read", "_ZN6Inject10injectReadEiPvm", 
                             "_ZN6Inject11setReadAddrEl", mmapRetAddr);
    assert(mmapRetAddr);

    mmapRetAddr = syscallJmp("send", "_ZN6Inject10injectSendEiPKvmi", 
                             "_ZN6Inject11setSendAddrEl", mmapRetAddr);
    assert(mmapRetAddr);

    mmapRetAddr = syscallJmp("write", "_ZN6Inject11injectWriteEiPKvm", 
                             "_ZN6Inject12setWriteAddrEl", mmapRetAddr);
    assert(mmapRetAddr);

    return true;
}

int Infector::remoteFuncJump(Elf64_Addr &srcAddr, 
                              Elf64_Addr &dstAddr, 
                              Elf64_Addr &tmpAddr,
                              Elf64_Addr &setAddr)
{
    unsigned char origCode[MAX_OPCODE_SIZE] = {0};
    if (!pTargetOpt->readTarget(srcAddr, origCode, sizeof(origCode)))
        return -1;

    callRemoteFunc(setAddr, 0, tmpAddr);

    unsigned char injectCode[8] = {0};
    injectCode[0] = JMP_CMD;
    int offset = dstAddr - srcAddr - 5;
    memcpy(&injectCode[1], &offset, 4);
    if (!pTargetOpt->writeTarget(srcAddr, injectCode, sizeof(injectCode)))
        return -1;

    int cmdOffset = 0;
    xed_state_t dstate;
    dstate.mmode=XED_MACHINE_MODE_LONG_64;

    while (cmdOffset < 8)
    {
        xed_decoded_inst_zero_set_mode(xedd, &dstate);
        xed_ild_decode(xedd, origCode + cmdOffset, XED_MAX_INSTRUCTION_BYTES);
        cmdOffset += xed_decoded_inst_get_length(xedd);
    }

    offset = srcAddr - tmpAddr - 5;
    origCode[cmdOffset] = JMP_CMD;
    memcpy(&origCode[cmdOffset+1], &offset, 4);
    if (!pTargetOpt->writeTarget(tmpAddr, origCode, sizeof(origCode)))
        return -1;
    
    return cmdOffset + JMP_SIZE;
}