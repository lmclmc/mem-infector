#include "version.h"

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
    pCmd->add<std::vector<int>>("-p", "--pid", "set target pid", {}, {1, 1000000});
    pCmd->add<std::list<std::string>>("-l", "--link", "set libso name", 
                                      {"--pid"});
    pCmd->add<std::vector<std::string>>("-ga", "--getfunaddr", 
                            "get target process function addr", {"--pid"});
    pCmd->add<std::vector<std::string>>("-sl", "--setloglevel", 
                            "set log level", {},
                            std::vector<std::string>({"info", "error",
                                        "debug", "warning", "all"}));
    pCmd->add<std::vector<std::string>>("-o", "--outputfile", "set output log file");
    pCmd->add<std::vector<std::string>>("-ca", "--call", "call functoin", {"--pid"});
    pCmd->add<std::vector<std::string>>("-sa", "--setaddr", "set target mem addr", {"--pid"});
    pCmd->add<std::vector<std::string>>("-w", "--write", "write str to target mem", {"--pid", "--setaddr"});
    pCmd->add<std::vector<int>>("-r", "--read", "read str from target mem", {"--pid", "--setaddr"});
    pCmd->add<std::vector<std::string>>("-pa", "--param", "set function parameter",{"--pid", "--call"});
    pCmd->add("-d", "--debug", "debug mode");
    pCmd->add("-v", "--version", "get version");
    pCmd->parse(false, argc, argv);

    bool ret = pCmd->get("--version");
    if (ret)
    {
        std::cout << "version: " << PROJECT_VERSION << std::endl;
        exit(0);
    }
    
    std::vector<std::string> strVector;
    ret = pCmd->get("--setloglevel", strVector);
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
    
    std::vector<int> intVector;
    ret = pCmd->get("--pid", intVector);
    if (!ret || !intVector.size())
    {
        LOGGER_INFO << "please set --pid";
        return 0;
    }
 
    Infector infector(intVector[0], LIBC_SO);
    ret = pCmd->get("--setaddr", strVector);
    if (ret && strVector.size())
    {
        Elf64_Addr targetAddr;
        sscanf(strVector[0].c_str(), "%lx", &targetAddr);
        LOGGER << LogFormat::addr << "targetAddr = " << targetAddr;
        infector.attachTarget();

        ret = pCmd->get("--write", strVector);
        if (ret && strVector.size())
        {
            if (infector.writeStrToTarget(targetAddr, strVector[0]))
            {
                LOGGER << "write " << strVector[0] << " successful";
            }
            else
            {
                LOGGER << "write " << strVector[0] << " failed";
            }
        }

        ret = pCmd->get("--read", intVector);
        if (ret && intVector.size())
        {
            std::string str;
            if (infector.readStrFromTarget(targetAddr, str, intVector[0]))
            {
                LOGGER << "read " << str << " successful";
            }
            else
            {
                LOGGER << "read " << str << " failed";
            }
        }
    }

    ret = pCmd->get("--call", strVector);
    if (ret && strVector.size())
    {
        ret = pCmd->get("--param", intVector);
        infector.loadAllSoFile();
        if (!infector.attachTarget())
        {
            LOGGER_ERROR << "attachTarget";
            return 0;
        }
        Elf64_Addr addr = infector.getSym(strVector[0]);
        if (!addr)
        {
            LOGGER_ERROR << "function parse failed";
            return 0;
        }

        LOGGER << strVector[0] << "   "<< LogFormat::addr << addr;

        for (int i = 0; i < 5; i++)
            intVector.push_back(0);

        Elf64_Addr ret = infector.callRemoteFunc(addr, intVector[0],
                                                 intVector[1],
                                                 intVector[2],
                                                 intVector[3],
                                                 intVector[4],
                                                 intVector[5]);
        if (ret)
        {
            LOGGER << "call " << strVector[0] << " successful " 
                   << "ret =  "<< LogFormat::addr << ret;
        }
        else
        {
            LOGGER << "call " << strVector[0] << " failed";
        }
    }

    
    ret = pCmd->get("--getfunaddr", strVector);
    if (ret)
    {
        infector.loadAllSoFile();
        for (auto &v : strVector)
        {
            LOGGER << v << "   "<< LogFormat::addr << infector.getSym(v);
        }
        return 0;
    }

    if (pCmd->get("--debug"))
    {
        Infector infector1(intVector[0], LIBC_SO);
        infector1.loadSoFile(LIBC_SO);
        return 0;
    }
    std::list<std::string> linkList;
    ret = pCmd->get("--link", linkList);
    if (ret && linkList.size())
    {
        if (!infector.attachTarget())
        {
            LOGGER_ERROR << "attachTarget";
            return 0;
        }

        infector.injectEvilSoname(linkList.front());

        infector.injectSysTableInit();
    }
    

    if (!infector.detachTarget())
    {
        return 0;
    }
}