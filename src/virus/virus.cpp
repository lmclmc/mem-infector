#include "infector/infector.h"
#include "infector/cmdline.h"
#include "log/log.h"

#include <elf.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <string.h>

#include <sys/types.h>
#include <sys/wait.h>

int main(int argc, char *argv[])
{
    cmdline::parser cmd;
    cmd.add<int>("pid", 'p', "set target pid", true, 0, cmdline::range(1, 1000000));
    cmd.add<std::string>("libso", 'l', "set libso name", false, "");

    cmd.parse_check(argc, argv);

    int pid = cmd.get<int>("pid");
    const char *injectso = cmd.get<std::string>("libso").c_str();
    Infector infector(pid);
    if (!infector.attachTarget())
    {
        LOGGER_ERROR << "attachTarget";
        return 0;
    }
    if (!infector.loadSoFile("libc-2.31.so"))
    {
        LOGGER_ERROR << "loadSoFile";
        return 0;
    }
    Elf64_Addr mallocAddr = infector.getSym("libc-2.31.so", "malloc");
    Elf64_Addr dlopenAddr = infector.getSym("libc-2.31.so", "__libc_dlopen_mode");
  
    Elf64_Addr retAddr = infector.callRemoteFunc(mallocAddr, 1000);
 
    if (!infector.writeStrToTarget(retAddr, injectso))
    {
        LOGGER_ERROR << "writeStrToTarget";
        return 0;
    }

    retAddr = infector.callRemoteFunc(dlopenAddr, retAddr, RTLD_NOW|RTLD_GLOBAL, 0);

    if (!infector.loadSoFile("libinject.so"))
    {
        LOGGER_ERROR << "loadSoFile";
        return 0;
    }
                                                                   
    infector.injectSysTableInit();

    if (!infector.detachTarget())
    {
        return 0;
    }
}