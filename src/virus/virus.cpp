#include "infector/infector.h"
#include "infector/targetopt.h"
#include "infector/cmdline.h"
#include <elf.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <string.h>

int main(int argc, char *argv[])
{
    cmdline::parser cmd;
    cmd.add<int>("pid", 'p', "set target pid", true, 0, cmdline::range(1, 1000000));
    cmd.add<std::string>("libso", 'l', "set libso name", false, "");

    cmd.parse_check(argc, argv);

    int pid = cmd.get<int>("pid");
    const char *injectso = cmd.get<std::string>("libso").c_str();
    printf("%s\n", injectso);
    Infector infector(pid);
     printf("=== %s, %d\n", __func__, __LINE__);
    if (!infector.attachTarget())
    {
        printf("=== %s, %d\n", __func__, __LINE__);
        return 0;
    }
     printf("=== %s, %d\n", __func__, __LINE__);
    if (!infector.loadSoFile("libc-2.31.so"))
    {
        printf("=== %s, %d\n", __func__, __LINE__);
        return 0;
    }
 printf("=== %s, %d\n", __func__, __LINE__);
    Elf64_Addr mallocAddr = infector.getSym("libc-2.31.so", "malloc");
    Elf64_Addr dlopenAddr = infector.getSym("libc-2.31.so", "__libc_dlopen_mode");
    Elf64_Addr acceptAddr = infector.getSym("libc-2.31.so", "accept");
    Elf64_Addr mmapAddr = infector.getSym("libc-2.31.so", "mmap");
     printf("mmapAddr === %s, %d, %p\n", __func__, __LINE__, mmapAddr);
      printf("__libc_dlopen_mode === %s, %d, %p\n", __func__, __LINE__, dlopenAddr);
    Elf64_Addr retAddr = infector.callRemoteFunc(mallocAddr, 1000);
    printf("retAddr = %p\n", retAddr);
    if (!infector.writeStrToTarget(retAddr, injectso))
    {
        printf("=== %s, %d\n", __func__, __LINE__);
        return 0;
    }
    retAddr = infector.callRemoteFunc(dlopenAddr, retAddr, RTLD_NOW|RTLD_GLOBAL, 0);
    printf("retAddr = %p\n", retAddr);

    if (!infector.loadSoFile("libinject.so"))
    {
        printf("=== %s, %d\n", __func__, __LINE__);
        return 0;
    }
    Elf64_Addr setAcceptAddr = infector.getSym("libinject.so", "_Z13setAcceptAddrl");
    Elf64_Addr injectAcceptAddr = infector.getSym("libinject.so", "_Z12injectAcceptiP8sockaddrPj");
                                                                   
                                                              //     _Z7tAcceptiP8sockaddrPj
    printf("setAcceptAddr = %p\n", setAcceptAddr);
    printf("injectAcceptAddr = %p\n", injectAcceptAddr);
    retAddr = infector.callRemoteFunc(mmapAddr, 0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

   infector.remoteFuncJump(acceptAddr, injectAcceptAddr, retAddr, setAcceptAddr);


    if (!infector.detachTarget())
    {
        printf("=== %s, %d\n", __func__, __LINE__);
        return 0;
    }
}