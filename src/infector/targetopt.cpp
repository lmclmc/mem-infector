#include "targetopt.h"
#include "log.h"

#include <sys/ptrace.h>
#include <sys/user.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>

#define MAPS_PATH_LEN 64
#define LINE_LEN 512

TargetOpt::TargetOpt(int pid_) :
    pid(pid_),
    isAttach(false)
{}

bool TargetOpt::attachTarget()
{
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) 
    {
        LOGGER_ERROR << "PTRACE_ATTACH: " << strerror(errno);
        return false;
    }
 
    isAttach = true;

    waitpid(pid, NULL, 0); 
    return true;
}

bool TargetOpt::detechTarget()
{
    if (!isAttach)
    {
        LOGGER_DEBUG << "target process isn't attach";
        return false;
    }

    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0)
    {
        LOGGER_ERROR << "PTRACE_DETACH: " << strerror(errno);
        return false;
    }

    return true;
}

bool TargetOpt::readTarget(unsigned long addr, void *vptr, int len)
{
    if (!isAttach)
    {
        LOGGER_WARNING << "target process isn't attach";
        return false;
    }

    int i,count;
    long word;
    long *ptr = (long *)vptr;
    i = count = 0;
    while (count < len) 
    {
        word = ptrace(PTRACE_PEEKTEXT, pid, addr + count, NULL);
        while(word < 0)
        {
            if(errno == 0)
                break;

            LOGGER_ERROR << "PTRACE_PEEKTEXT: " << strerror(errno);
            return false;
        }
        count += 8;
        ptr[i++] = word;
    }
    return true;
}

bool TargetOpt::writeTarget(unsigned long addr, const void *vptr, int len)
{
    if (!isAttach)
    {
        LOGGER_WARNING << "target process isn't attach";
        return false;
    }

    int count;
    long word;

    count = 0;

    while (count < len) 
    {
        memcpy(&word, vptr + count, sizeof(word));
        word = ptrace(PTRACE_POKETEXT, pid, addr + count, word);
        count += 8;

        if(errno != 0)
        {
            LOGGER_ERROR << "PTRACE_POKETEXT: " << strerror(errno);
            return false;
        }
    }
    return true;
}

bool TargetOpt::readTarget(struct user_regs_struct &regs)
{ 
    if (!isAttach)
    {
        LOGGER_WARNING << "target process isn't attach";
        return false;
    }

    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0)
    {
        LOGGER_ERROR << "PTRACE_GETREGS: " << strerror(errno);
        return false;
    }

    return true;
}

bool TargetOpt::writeTarget(struct user_regs_struct &regs)
{
    if (!isAttach)
    {
        LOGGER_WARNING << "target process isn't attach";
        return false;
    }

    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) < 0)
    {
        LOGGER_ERROR << "PTRACE_SETREGS: " << strerror(errno);
        return false;
    }

    return true;
}

bool TargetOpt::contTarget()
{
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0)
    {
        LOGGER_ERROR << "PTRACE_CONT: " << strerror(errno);
        return false;
    }

    return true;
}

bool TargetOpt::getTargetSoInfo(const std::string &libsoname, 
                                std::string &soPath, 
                                Elf64_Addr &baseAddr)
{
    char mapsPath[MAPS_PATH_LEN];
    char line[LINE_LEN], tmp[32];
    char *p, *start;
    int i;

    snprintf(mapsPath, sizeof(mapsPath), "/proc/%d/maps", pid);
    FILE *fp;
    if ((fp = fopen(mapsPath, "r")) == NULL) 
    {
        LOGGER_ERROR << "fopen: " << strerror(errno);
        return false;
    }

    while (fgets(line, sizeof(line), fp)) {
        if ((p = strchr(line, '/')) == NULL) 
            continue;

        *(char *)strchr(p, '\n') = '\0';

        if (!strstr(p, libsoname.c_str())) 
            continue;

        soPath = p;

        for (i = 0, start = tmp, p = line; *p != '-'; i++, p++)
            start[i] = *p;
                
        start[i] = '\0';

        fclose(fp);

        unsigned long long a1 = strtoull(start+4, NULL, 16);
        a1 &= 0xffffffff;
        start[4] = 0x0;
        unsigned long long a2 = strtoull(start, NULL, 16);
        baseAddr = (a2 << 32) + a1;
        return true;
    }
    
    baseAddr = 0;
    fclose(fp);
    return false;
}