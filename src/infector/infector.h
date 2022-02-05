#ifndef INFECTOR_H_
#define INFECTOR_H_

#include <vector>
#include <iostream>
#include <functional>
#include <map>
#include <elf.h>

#define MAX_ARG_NUM 7

class TargetOpt;
struct xed_decoded_inst_s;
typedef struct xed_decoded_inst_s xed_decoded_inst_t;

class Infector final
{
public:
    using SymTab = std::map<std::string, long>;
    using SymTabs = std::map<std::string, SymTab>;

    Infector(int pid);
    ~Infector();

    bool injectSysTableInit();

    long getSym(const std::string &, const std::string &);
    bool loadSoFile(const std::string &);

    bool attachTarget();
    bool detachTarget();

    int remoteFuncJump(Elf64_Addr &, Elf64_Addr &, Elf64_Addr &, Elf64_Addr &);

    template<class ...Args>
    long callRemoteFunc(Args ...args)
    {       
        constexpr int argsNum = sizeof...(args);
        static_assert(argsNum <= MAX_ARG_NUM, 
                     "the number of parameters is more than MAX_ARG_NUM");

        if (!backupTarget())
            return 0;

        callRemoteFuncIdx<0>(args...);

        if (!updateTarget())
            return 0;

        return restoreTarget();
    }

    bool writeStrToTarget(Elf64_Addr &, const std::string &);

private:
    template<int idx, class T, class ...Args>
    void callRemoteFuncIdx(T t, Args ...args)
    {
        mRegvec[idx](t);
        return callRemoteFuncIdx<idx+1>(args...);
    }

    template<int idx, class T>
    void callRemoteFuncIdx(T t)
    {
        mRegvec[idx](t);
        return;
    }

    void regvecInit();

    bool backupTarget(); 

    bool updateTarget();

    long restoreTarget();

    bool getSoInfo(const std::string &, std::string &, Elf64_Addr &);

    Elf64_Addr syscallJmp(const std::string &, const std::string &, 
                          const std::string &, Elf64_Addr);

private:
    std::vector<std::function<void(long)>> mRegvec;
    SymTabs symTabs;

    int mPid;
    struct user_regs_struct *pNewRegs;
    struct user_regs_struct *pOrigRegs;
    TargetOpt *pTargetOpt;
    xed_decoded_inst_t *xedd;

    unsigned char backupCode[8] = {0};
};

#endif
