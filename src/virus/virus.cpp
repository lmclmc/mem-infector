#include "infector/infector.h"
#include "cmdline/cmdline.h"
#include "single/single.hpp"
#include "log/log.h"

#include <elf.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <string.h>
#include <vector>
#include <sys/types.h>
#include <sys/wait.h>

#define LIBC_SO "libc-2.31.so"

using namespace lmc;

int main(int argc, char *argv[])
{
    CmdLine *pCmd = TypeSingle<CmdLine>::getInstance();
    pCmd->add<std::vector, int>("-p", "--pid", "set target pid");
    pCmd->add<std::vector, std::string>("-l", "--link", "set libso name");

    pCmd->parse(argc, argv);

    std::vector<int> pidVector;
    std::vector<std::string> linkVector;
    bool ret = pCmd->get("--pid", pidVector);
    ret = pCmd->get("--link", linkVector);
    Infector infector(pidVector[0], LIBC_SO);
    if (!infector.attachTarget())
    {
        LOGGER_ERROR << "attachTarget";
        return 0;
    }

    infector.injectEvilSoname(linkVector[0]);

    infector.injectSysTableInit();

    if (!infector.detachTarget())
    {
        return 0;
    }
}