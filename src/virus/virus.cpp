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
    pCmd->add<std::vector, std::string>("-ga", "--getaddr", 
                                        "get target process function addr");
    pCmd->add<std::vector, std::string>("-sl", "--setloglevel", 
                                        "set log level");
    pCmd->add<std::vector, std::string>("-o", "--outputfile", 
                                        "set output log file");
    pCmd->add("-d", "--debug", "debug mode");
    pCmd->parse(argc, argv);

    std::vector<std::string> strVector;
    bool ret = pCmd->get("--setloglevel", strVector);
    if (ret && strVector.size())
    {
        for (auto &s : strVector)
        {
            if (s == "close")
                Logger::setLevel(LogLevel::close);
            else if (s == "info")
                Logger::setLevel(LogLevel::info);
            else if (s == "warning")
                Logger::setLevel(LogLevel::warning);
            else if (s == "debug")
                Logger::setLevel(LogLevel::debug);
            else if (s == "error")
                Logger::setLevel(LogLevel::error);
            else if (s == "all")
                Logger::setLevel(LogLevel::all);
        }
    }

    ret = pCmd->get("--outputfile", strVector);
    if (ret && strVector.size())
        Logger::setOutputFile(strVector[0]);
    
    std::vector<int> pidVector;
    ret = pCmd->get("--pid", pidVector);
    if (!ret || !pidVector.size())
    {
        LOGGER_INFO << "please set --pid";
        return 0;
    }
        
    
    std::vector<std::string> funaddrVector;
    Infector infector(pidVector[0], LIBC_SO);
    ret = pCmd->get("--getaddr", funaddrVector);
    if (ret)
    {
        infector.loadAllSoFile();
        for (auto &v : funaddrVector)
        {
            LOGGER << v << "   "<< LogFormat::addr << infector.getSym(v);
        }
        return 0;
    }

    if (pCmd->get("--debug"))
    {
        Infector infector1(pidVector[0], LIBC_SO);
        infector1.loadSoFile(LIBC_SO);
        return 0;
    }
    std::vector<std::string> linkVector;
    ret = pCmd->get("--link", linkVector);
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