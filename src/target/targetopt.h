#ifndef TARGETOPT_H_
#define TARGETOPT_H_

#include <string>
#include <elf.h>
#include <map>

class TargetMaps
{
    typedef struct ELFADDR_START_END
    {
        Elf64_Addr start_addr;
        Elf64_Addr end_addr;
    }ELFADDR_START_END;

public:
    TargetMaps(int);
    virtual ~TargetMaps(){}

    void clearMapInfos();
    bool readTargetAllMaps();
    std::map<std::string, ELFADDR_START_END> &getMapInfo();

private:
    int pid;
    std::map<std::string, ELFADDR_START_END> mapInfos;
};

class TargetOpt : public TargetMaps
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

    std::map<Elf64_Addr, std::string> searchStrInTarget(std::string &);
    
private:
    int pid;

    bool isAttach;
};

#endif