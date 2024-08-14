#include <iostream>
#include <unistd.h>
#include <string.h>
#include <sys/user.h>

#include "target/targetopt.h"
#include "log/log.h"
#include <sys/mman.h>
#define WECHAT_OFFSET 0x96df27
//#define WECHAT_OFFSET 0x96df0a
void __attribute__((constructor)) wechat_hook_init(void) {
    printf("Dynamic library loaded: Running initialization.\n");
    lmc::Logger::setLevel(LogLevel::all);
    TargetMaps target(getpid());
    Elf64_Addr wechat_baseaddr = 0;
    Elf64_Addr libx_baseaddr = 0;
    Elf64_Addr first_nop_cmd_addr = 0;
    Elf64_Addr second_nop_cmd_addr = 0;
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

        unsigned char *nop_cmd_byte = (unsigned char *)libx_baseaddr;
        for (int i = 0; i < 0x1000000; i++)
        {
            if (!memcmp(&nop_cmd_byte[i], buffer, sizeof(buffer)))
            {
                if (first_nop_cmd_addr)
                {
                    second_nop_cmd_addr = (Elf64_Addr)&nop_cmd_byte[i];
                    LOGGER_INFO << "second search successful   " << LogFormat::addr << second_nop_cmd_addr;
                    break;
                } else {
                    first_nop_cmd_addr = (Elf64_Addr)&nop_cmd_byte[i];
                    LOGGER_INFO << "first search successful   " << LogFormat::addr << first_nop_cmd_addr;
                    i += 16;
                    continue;
                }
            }
        }

        if (mprotect((void *)(wechat_baseaddr), 0x1000000, PROT_WRITE | PROT_READ | PROT_EXEC) < 0)
        {
            
        }

        if (mprotect((void *)(libx_baseaddr), 0x10000, PROT_WRITE | PROT_READ | PROT_EXEC) < 0)
        {
            
        }
        
        memcpy((unsigned char *)second_nop_cmd_addr, (unsigned char *)wechat_baseaddr + WECHAT_OFFSET, 12);

        unsigned char movabs_wechat_buffer[10];
        memset(movabs_wechat_buffer, 0, sizeof(movabs_wechat_buffer));
        Elf64_Addr wechat_hook_point_addr = (Elf64_Addr)wechat_baseaddr + WECHAT_OFFSET + 12;
        movabs_wechat_buffer[0] = 0x48;
        movabs_wechat_buffer[1] = 0xb8;
        memcpy(&movabs_wechat_buffer[2], &wechat_hook_point_addr, 8);
        memcpy((unsigned char *)second_nop_cmd_addr + 12, movabs_wechat_buffer, 10);

        unsigned char jmp_wechat_buffer[2];
        jmp_wechat_buffer[0] = 0xff;
        jmp_wechat_buffer[1] = 0xe0;
        memcpy((unsigned char *)second_nop_cmd_addr + 22, jmp_wechat_buffer, 2);

        unsigned char movabs_buffer[10];
        memset(movabs_buffer, 0, sizeof(movabs_buffer));
        movabs_buffer[0] = 0x48;
        movabs_buffer[1] = 0xb8;
        memcpy(&movabs_buffer[2], &first_nop_cmd_addr, 8);
        memcpy((unsigned char *)wechat_baseaddr + WECHAT_OFFSET, movabs_buffer, 10);
  
        unsigned char jmp_buffer[2];
        jmp_buffer[0] = 0xff;
        jmp_buffer[1] = 0xe0;
        memcpy((unsigned char *)wechat_baseaddr + WECHAT_OFFSET + 10, jmp_buffer, 2);

        if (mprotect((void *)(wechat_baseaddr), 0x1000000, PROT_READ | PROT_EXEC) < 0)
        {
            
        }

        if (mprotect((void *)(libx_baseaddr), 0x10000, PROT_READ | PROT_EXEC) < 0)
        {
            
        }
    }
}

static void wechat_hook_core(struct user_regs_struct *regs)
{
    if (regs->r8 > 0x5016f3e7d290 && regs->r8 < 0x7ffffff7d290)
    {
        LOGGER_INFO << (char *)regs->r8;
    }
    if (regs->r9 > 0x5016f3e7d290 && regs->r9 < 0x7ffffff7d290)
    {
        LOGGER_INFO << (char *)regs->r9;
    }
    if (regs->r10 > 0x5016f3e7d290 && regs->r10 < 0x7ffffff7d290)
    {
        LOGGER_INFO << (char *)regs->r10;
    }
    if (regs->r11 > 0x5016f3e7d290 && regs->r11 < 0x7ffffff7d290)
    {
        LOGGER_INFO << (char *)regs->r11;
    }
    if (regs->r12 > 0x5016f3e7d290 && regs->r12 < 0x7ffffff7d290)
    {
        LOGGER_INFO << (char *)regs->r12;
    }
    if (regs->r13 > 0x5016f3e7d290 && regs->r13 < 0x7ffffff7d290)
    {
        LOGGER_INFO << (char *)regs->r13;
    }
    if (regs->rsi > 0x5016f3e7d290 && regs->rsi < 0x7ffffff7d290)
    {
        LOGGER_INFO << (char *)regs->rsi;
    }
    if (regs->rdi > 0x5016f3e7d290 && regs->rdi < 0x7ffffff7d290)
    {
        LOGGER_INFO << (char *)regs->rdi;
    }
    if (regs->rsi > 0x5016f3e7d290 && regs->rsp < 0x7ffffff7d290)
    {
        LOGGER_INFO << (char *)regs->rsp;
    }
    if (regs->rdi > 0x5016f3e7d290 && regs->rbp < 0x7ffffff7d290)
    {
        LOGGER_INFO << (char *)regs->rbp;
    }
}

static void wechat_hook_run()
{
    struct user_regs_struct regs = {0};
    asm volatile (
        "mov %%rbx, %0\n"
        "mov %%rcx, %1\n"
        "mov %%rdx, %2\n"
        "mov %%rsi, %3\n"
        "mov %%rdi, %4\n"
        "mov %%rbp, %5\n"
        "mov %%rsp, %6\n"
        "mov %%r8, %7\n"
        "mov %%r9, %8\n"
        "mov %%r10, %9\n"
        "mov %%r11, %10\n"
        "mov %%r12, %11\n"
        "mov %%r13, %12\n"
        "mov %%r14, %13\n"
        "mov %%r15, %14\n"
        : "=m"(regs.rbx), "=m"(regs.rcx), "=m"(regs.rdx),
          "=m"(regs.rsi), "=m"(regs.rdi), "=m"(regs.rbp), "=m"(regs.rsp),
          "=m"(regs.r8), "=m"(regs.r9), "=m"(regs.r10), "=m"(regs.r11),
          "=m"(regs.r12), "=m"(regs.r13), "=m"(regs.r14), "=m"(regs.r15)
        :
        : "memory"
    );
    wechat_hook_core(&regs);
    asm volatile (
        "mov %0, %%rbx\n"
        "mov %1, %%rcx\n"
        "mov %2, %%rdx\n"
        "mov %3, %%rsi\n"
        "mov %4, %%rdi\n"
        "mov %5, %%r8\n"
        "mov %6, %%r9\n"
        "mov %7, %%r10\n"
        "mov %8, %%r11\n"
        "mov %9, %%r12\n"
        "mov %10, %%r13\n"
        "mov %11, %%r14\n"
        "mov %12, %%r15\n"
        "mov %13, %%rbp\n"
        "mov %14, %%rsp\n"
        :
        : "m"(regs.rbx), "m"(regs.rcx), "m"(regs.rdx),
          "m"(regs.rsi), "m"(regs.rdi), "m"(regs.r8), 
          "m"(regs.r9), "m"(regs.r10), "m"(regs.r11),
          "m"(regs.r12), "m"(regs.r13), "m"(regs.r14), "m"(regs.r15),"m"(regs.rbp), "m"(regs.rsp)
        : "memory"
    );
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
   // printf("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    wechat_hook_run();
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