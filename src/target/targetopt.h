#ifndef TARGETOPT_H_
#define TARGETOPT_H_

#include <string>
#include <elf.h>
#include <list>

typedef struct MapInfo_
{
    MapInfo_(int size_, Elf64_Addr baseAddr_, const std::string &mapName_) :
        size(size_), baseAddr(baseAddr_), mapName(mapName_){}

    int size;
    Elf64_Addr baseAddr;
    std::string mapName;
}MapInfo;

class TargetMaps
{
public:
    TargetMaps(int);
    virtual ~TargetMaps(){}

    bool getTargetSoInfo(const std::string &, std::string &, Elf64_Addr &);

    bool getHeapInfo(Elf64_Addr &, long &);

    bool getStackInfo(Elf64_Addr &, long &);

    bool readTargetAllMaps();
    std::list<MapInfo> &getMapInfo();

private:
    bool readTargetMaps(const std::string &,std::string &, Elf64_Addr &, long &);

private:
    int pid;
    std::list<MapInfo> mapInfos;
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

private:
    int pid;

    bool isAttach;
};

#endif