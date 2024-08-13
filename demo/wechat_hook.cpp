#include <iostream>
#include <unistd.h>
#include <string.h>

#include "target/targetopt.h"
#include "log/log.h"
#include <sys/mman.h>

void __attribute__((constructor)) wechat_hook_init(void) {
    printf("Dynamic library loaded: Running initialization.\n");
    lmc::Logger::setLevel(LogLevel::all);
    TargetMaps target(getpid());
    Elf64_Addr wechat_baseaddr = 0;
    Elf64_Addr libx_baseaddr = 0;
    Elf64_Addr libx_jmp = 0;
    if (target.readTargetAllMaps())
    {
        auto &maps = target.getMapInfo();
        for (auto &m : maps)
        {
            if (m.first.find("wechat.patch") != std::string::npos)
            {
                wechat_baseaddr = m.second;
                LOGGER_INFO << m.first << " :: " << LogFormat::addr << m.second;
            }

            if (m.first.find("libX.so") != std::string::npos)
            {
                libx_baseaddr = m.second;
                LOGGER_INFO << m.first << " :: " << LogFormat::addr << m.second;
            } 
        }

        unsigned char buffer[16] = {0x90};
        memset(buffer, 0x90, sizeof(buffer));

        unsigned char *cmd_byte = (unsigned char *)libx_baseaddr;
        for (int i = 0; i < 0x100000; i++)
        {
            if (!memcmp(&cmd_byte[i], buffer, sizeof(buffer)))
            {
                libx_jmp = (Elf64_Addr)&cmd_byte[i];
                LOGGER_INFO << "search successful" << LogFormat::addr << libx_jmp;
                break;
            }
        }

        if (mprotect((void *)(wechat_baseaddr), 0x1000000, PROT_WRITE | PROT_READ | PROT_EXEC) < 0)
        {
            
        }
        return;
        unsigned char movabs_buffer[10];
        memset(movabs_buffer, 0, sizeof(movabs_buffer));
        movabs_buffer[0] = 0x48;
        movabs_buffer[1] = 0xb8;
        memcpy(&movabs_buffer[2], &libx_jmp, 8);
        memcpy((unsigned char *)wechat_baseaddr + 0x96df2a, movabs_buffer, 10);
  
        unsigned char jmp_buffer[2];
        jmp_buffer[0] = 0xff;
        jmp_buffer[1] = 0xe0;
        memcpy((unsigned char *)wechat_baseaddr + 0x96df34, jmp_buffer, 2);
        if (mprotect((void *)(wechat_baseaddr), 4096, PROT_READ | PROT_EXEC) < 0)
        {
            
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
    printf("wechat hook point11111111111111111111111111111111111111111111111111111111111111\n");
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