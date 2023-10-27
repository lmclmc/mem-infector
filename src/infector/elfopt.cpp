#include "elfopt.h"
#include "log/log.h"
#include "threadpool/workqueue.h"
#include "util/single.hpp"

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

using namespace lmc;

Elf64SectionWrapper::Elf64SectionWrapper()
{
    mSecTab[SECTION_DYNSYM_STR] = std::make_shared<Elf64DynsymSection>();
    mSecTab[SECTION_RELADYN_STR] = std::make_shared<Elf64RelaDynSectoin>();
}

Elf64SectionWrapper::SecTab &Elf64SectionWrapper::getSecTab()
{
    return mSecTab;
}

long Elf64Wrapper::getSectionAddr(const std::string &soname, 
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

    std::promise<uint64_t> dynstrPromise;
    std::future<uint64_t> dynstrFuture = dynstrPromise.get_future();

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
        } 

        pSecTable[section.section_name]->pushSection(pMmap, 
                                                     section, 
                                                     baseAddr);
    }

    dynsymFuture.get();
    reladynFuture.get();

    if (munmap(pMmap, st.st_size) == -1)
        LOGGER_ERROR << strerror(errno);

    if (close(mFd) == -1)
    {
        LOGGER_ERROR << strerror(errno);
        return false;
    }

    return true;
}

Elf64Section::SymTab Elf64Section::symTab;

std::string Elf64DynsymSection::getSymbolType(uint8_t &sym_type) 
{
    switch(ELF32_ST_TYPE(sym_type)) {
        case 0: return "NOTYPE";
        case 1: return "OBJECT";
        case 2: return "FUNC";
        case 3: return "SECTION";
        case 4: return "FILE";
        case 6: return "TLS";
        case 7: return "NUM";
        case 10: return "LOOS";
        case 12: return "HIOS";
        default: return "UNKNOWN";
    }
}

std::string Elf64DynsymSection::getSymbolBind(uint8_t &sym_bind) 
{
    switch(ELF32_ST_BIND(sym_bind)) {
        case 0: return "LOCAL";
        case 1: return "GLOBAL";
        case 2: return "WEAK";
        case 3: return "NUM";
        case 10: return "UNIQUE";
        case 12: return "HIOS";
        case 13: return "LOPROC";
        default: return "UNKNOWN";
    }
}

std::string Elf64DynsymSection::getSymbolVisibility(uint8_t &sym_vis)
{
    switch(ELF32_ST_VISIBILITY(sym_vis)) {
        case 0: return "DEFAULT";
        case 1: return "INTERNAL";
        case 2: return "HIDDEN";
        case 3: return "PROTECTED";
        default: return "UNKNOWN";
    }
}

std::string Elf64DynsymSection::getSymbolIndex(uint16_t &sym_idx) 
{
    switch(sym_idx) {
        case SHN_ABS: return "ABS";
        case SHN_COMMON: return "COM";
        case SHN_UNDEF: return "UND";
        case SHN_XINDEX: return "COM";
        default: return std::to_string(sym_idx);
    }
}

void Elf64RelaDynSectoin::pushSectionS(uint8_t *pMmap, 
                                       Section &section, 
                                       Elf64_Addr baseAddr,
                                       uint64_t userdata)
{
    uint64_t relapltSize = userdata;
    auto total_syms = (section.section_size + relapltSize) / sizeof(Elf64_Rela);
    auto syms_data = (Elf64_Rela*)(pMmap + section.section_offset);
    for (int i = 0; i < total_syms; i++)
    {
        uint64_t idx = syms_data[i].r_info >> 32;
        for (auto &l : symTab)
        {
            if (l.symbol_idx == idx)
            {
                l.symbol_rela_table[i] = syms_data[i];
                break;
            }
        }
    }
}

void Elf64DynsymSection::pushSectionS(uint8_t *pMmap, 
                                      Section &section, 
                                      Elf64_Addr baseAddr,
                                      uint64_t userdata)
{
    auto total_syms = section.section_size / sizeof(Elf64_Sym);
    auto syms_data = (Elf64_Sym*)(pMmap + section.section_offset);
    char *pDynStr = (char *)pMmap + userdata;

    Symbol symbol;
    for (int i = 0; i < total_syms; ++i) {
        if (section.section_type != SHT_DYNSYM) 
            continue;
            
        symbol.symbol_idx        = i;
        symbol.symbol_value      = syms_data[i].st_value + baseAddr;
        symbol.symbol_size       = syms_data[i].st_size;
        symbol.symbol_info       = syms_data[i].st_info;
        symbol.symbol_other       = syms_data[i].st_other;
        symbol.symbol_type       = getSymbolType(syms_data[i].st_info);
        symbol.symbol_bind       = getSymbolBind(syms_data[i].st_info);
        symbol.symbol_visibility = getSymbolVisibility(syms_data[i].st_other);
        symbol.symbol_index_str  = getSymbolIndex(syms_data[i].st_shndx);
        symbol.symbol_index      = syms_data[i].st_shndx;
        symbol.symbol_section    = section.section_name;  

        symbol.symbol_name_addr = syms_data[i].st_name;
        symbol.symbol_name = std::string(pDynStr + syms_data[i].st_name);
        symTab.emplace_back(symbol);
    }
}

long Elf64Wrapper::getSymAddr(const std::string &soname, 
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

long Elf64DynsymSection::getSymAddr(const std::string &symname)
{
    for (auto &l : symTab)
    {
        if (l.symbol_name == symname)
            return l.symbol_value;
    }

    return 0;
}

Elf64Section::SymTab &Elf64Section::getSymTab()
{
    return symTab;
}