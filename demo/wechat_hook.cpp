#include <iostream>
#include <unistd.h>

#include "target/targetopt.h"
#include "log/log.h"

void __attribute__((constructor)) wechat_hook_init(void) {
    printf("Dynamic library loaded: Running initialization.\n");
    lmc::Logger::setLevel(LogLevel::all);
    TargetMaps target(getpid());
    Elf64_Addr wechat_baseaddr = 0;
    Elf64_Addr libx_baseaddr = 0;
    if (target.readTargetAllMaps())
    {
        auto &maps = target.getMapInfo();
        for (auto &m : maps)
        {
            if (m.first.find("wechat.test") != std::string::npos)
            {
                wechat_baseaddr = m.second;
                LOGGER_INFO << m.first << " :: " << LogFormat::addr << m.second;
            }

            if (m.first.find("libX.so") != std::string::npos)
            {
                wechat_baseaddr = m.second;
                LOGGER_INFO << m.first << " :: " << LogFormat::addr << m.second;
            } 
        }
    } 
}

void wechat_hook()
{
    asm("nop;\n"
        "nop;\n"
        "nop;\n"
        "nop;\n"
        "nop;\n"
        "nop;\n"
        "nop;\n"
        "nop;\n"
        "nop;\n"
        "nop;\n"
        "nop;\n"
        "nop;\n"
        "nop;\n"
        "nop;\n"
        "nop;\n"
        "nop;\n"
    );
    printf("wechat hook point\n");
    asm("nop;\n"
        "nop;\n"
        "nop;\n"
        "nop;\n"
        "nop;\n"
        "nop;\n"
        "nop;\n"
        "nop;\n"
        "nop;\n"
        "nop;\n"
        "nop;\n"
        "nop;\n"
        "nop;\n"
        "nop;\n"
        "nop;\n"
        "nop;\n"
    );
}