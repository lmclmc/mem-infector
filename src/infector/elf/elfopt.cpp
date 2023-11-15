#include "elfopt.h"
#include "log/log.h"
#include "threadpool/workqueue.h"
#include "util/single.hpp"

#include "elf_dynsym.h"
#include "elf_reladyn.h"
#include "elf_gnuver_r.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>

#define SECTION_DYNSTR_STR ".dynstr"
#define SECTION_DYNSYM_STR ".dynsym"
#define SECTION_RELADYN_STR ".rela.dyn"
#define SECTION_RELAPLT_STR ".rela.plt"
#define SECTION_GNUVERSION_STR ".gnu.version_r"

using namespace lmc;

Elf64SectionWrapper::Elf64SectionWrapper()
{
    mSecTab[SECTION_DYNSYM_STR] = std::make_shared<Elf64DynsymSection>();
    mSecTab[SECTION_RELADYN_STR] = std::make_shared<Elf64RelaDynSectoin>();
    mSecTab[SECTION_GNUVERSION_STR] = std::make_shared<Elf64GnuVerSectoin>();
}

Elf64SectionWrapper::SecTab &Elf64SectionWrapper::getSecTab()
{
    return mSecTab;
}

uint32_t Elf64Wrapper::getSectionSize(const std::string &soname, 
                                      const std::string &sectionName)
{
    auto pSecWrapper = mSecWrapperTab[soname];
    if (pSecWrapper)
    {
        auto &pSecTab = pSecWrapper->getSecTab();
        if (pSecTab.find(sectionName) != pSecTab.end())
        {
            return pSecTab[sectionName]->getSectionSize();
        }
    }
    return 0;
}

Elf64_Addr Elf64Wrapper::getSectionAddr(const std::string &soname, 
                                        const std::string &sectionName)
{
    auto pSecWrapper = mSecWrapperTab[soname];
    if (pSecWrapper)
    {
        auto &pSecTab = pSecWrapper->getSecTab();
        if (pSecTab.find(sectionName) != pSecTab.end())
        {
            return pSecTab[sectionName]->getSectionAddr();
        }
    }
    return 0;
}

bool Elf64Wrapper::loadSo(const std::string &soname, Elf64_Addr baseAddr)
{
    struct stat st;

    if ((mFd = open(soname.c_str(), O_RDONLY)) < 0) 
    {
        LOGGER_ERROR << "open: " << soname << strerror(errno);
        return false;
    }

    if (fstat(mFd, &st) < 0) 
    {
        LOGGER_ERROR << "fstat: " << strerror(errno);
        return false;
    }

    pMmap = static_cast<uint8_t*>(mmap(NULL, st.st_size, PROT_READ, 
                                       MAP_PRIVATE, mFd, 0));
    if (pMmap == MAP_FAILED) 
    {
        LOGGER_ERROR << "mmap: " << strerror(errno);
        return false;
    }

    auto eHdr = (Elf64_Ehdr *)pMmap;
    if (eHdr->e_ident[EI_CLASS] != ELFCLASS64) 
    {
        LOGGER_ERROR << "Only 64-bit files supported";
        return false;
    }

    if (!mSecWrapperTab[soname])
        mSecWrapperTab[soname] = std::make_shared<Elf64SectionWrapper>();

    auto pSecWrapper = mSecWrapperTab[soname];
    auto &pSecTable = pSecWrapper->getSecTab();

    Elf64_Shdr *sHdr = (Elf64_Shdr*)(pMmap + eHdr->e_shoff);
    int shnum = eHdr->e_shnum;

    Elf64_Shdr *sStrtab = &sHdr[eHdr->e_shstrndx];
    const char *const pStrtab = (char *)pMmap + sStrtab->sh_offset;

    WorkQueue *work = TypeSingle<WorkQueue>::getInstance(MutexType::None);
    std::future<bool> dynsymFuture;
    std::future<bool> reladynFuture;
    std::future<bool> gnuversoinFuture;

    std::promise<uint64_t> dynstrPromise;
    std::shared_future<uint64_t> dynstrFuture = 
                                 dynstrPromise.get_future().share();

    std::promise<uint64_t> relapltPromise;
    std::future<uint64_t> relapltFuture = relapltPromise.get_future();
    
    for (int i = 0; i < shnum; ++i) 
    {
        Section section;
        section.section_index = i;
        section.section_name = std::string(pStrtab + sHdr[i].sh_name);
        section.section_type = sHdr[i].sh_type;
        section.section_addr = sHdr[i].sh_addr;
        section.section_offset = sHdr[i].sh_offset;
        section.section_size = sHdr[i].sh_size;
        section.section_ent_size = sHdr[i].sh_entsize;
        section.section_addr_align = sHdr[i].sh_addralign;
        if (!pSecTable[section.section_name])
        {
            pSecTable[section.section_name] = std::make_shared<Elf64Section>();
        }

        if (section.section_name == SECTION_DYNSTR_STR)
        {
            dynstrPromise.set_value(section.section_offset);
        } else if (section.section_name == SECTION_DYNSYM_STR)
        {
            dynsymFuture = work->addTask([&](uint8_t *pMap, 
                                             Section &section, 
                                             Elf64_Addr baseAddr){
                uint64_t offset = dynstrFuture.get();
                pSecTable[section.section_name]->pushSection(pMmap,
                                                             section,
                                                             baseAddr,
                                                             offset);
                return true;
            }, pMmap, section, baseAddr);
            continue;
        } else if (section.section_name == SECTION_RELADYN_STR)
        {
            reladynFuture = work->addTask([&](uint8_t *pMap, 
                                              Section &section, 
                                              Elf64_Addr baseAddr){
                uint64_t size = relapltFuture.get();
                pSecTable[section.section_name]->pushSection(pMmap,
                                                             section,
                                                             baseAddr,
                                                             size);
                return true;
            }, pMmap, section, baseAddr);
            continue;
        } else if (section.section_name == SECTION_RELAPLT_STR)
        {
            relapltPromise.set_value(section.section_size);
        } else if (section.section_name == SECTION_GNUVERSION_STR)
        {
            gnuversoinFuture = work->addTask([&](uint8_t *pMap, 
                                                 Section &section, 
                                                 Elf64_Addr baseAddr){
                uint64_t offset = dynstrFuture.get();
                pSecTable[section.section_name]->pushSection(pMmap,
                                                             section,
                                                             baseAddr,
                                                             offset);
                return true;
            }, pMmap, section, baseAddr);
            continue;
        }

        pSecTable[section.section_name]->pushSection(pMmap, 
                                                     section, 
                                                     baseAddr);
    }

    dynsymFuture.get();
    reladynFuture.get();
    gnuversoinFuture.get();

    if (munmap(pMmap, st.st_size) == -1)
        LOGGER_ERROR << strerror(errno);

    if (close(mFd) == -1)
    {
        LOGGER_ERROR << strerror(errno);
        return false;
    }

    return true;
}

Elf64_Addr Elf64Wrapper::getSymAddr(const std::string &soname, 
                                    const std::string &symname)
{
    auto pSecWrapper = mSecWrapperTab[soname];
    if (pSecWrapper)
    {
        auto pDynSymSec = std::dynamic_pointer_cast<Elf64DynsymSection>(
                               pSecWrapper->getSecTab()[SECTION_DYNSYM_STR]);
        if (pDynSymSec)
        {
            return pDynSymSec->getSymAddr(symname);
        }
    }

    return 0;
}

void Elf64Wrapper::clearAllSyms()
{
    mSecWrapperTab.clear();
}

Elf64Section::SymTab &Elf64Wrapper::getDynsymTab(const std::string &soname)
{
    auto pSecWrapper = mSecWrapperTab[soname];
    if (pSecWrapper)
    {
        for (auto &s : pSecWrapper->getSecTab())
        {
            if (s.second)
                return s.second->getSymTab();
        }
    }
}

Elf64Section::GnuVerTab &Elf64Wrapper::getGnuVerTab(const std::string &soname)
{
    auto pSecWrapper = mSecWrapperTab[soname];
    if (pSecWrapper)
    {
        for (auto &s : pSecWrapper->getSecTab())
        {
            if (s.second)
                return s.second->getGnuVerTab();
        }
    }
}