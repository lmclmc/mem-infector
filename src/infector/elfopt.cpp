#include "elfopt.h"
#include "log/log.h""

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>

#define MAX_SECTIONS 20

Elf64Wrapper::Elf64Wrapper() :
    pMmap(nullptr),
    mFd(0)
{
    mSecTab.resize(MAX_SECTIONS);
    mSecTab[SHT_STRTAB] = std::make_shared<Elf64StrtabSection>();
    mSecTab[SHT_DYNSYM] = std::make_shared<Elf64DynsymSection>();
}

bool Elf64Wrapper::loadSo(const std::string &soname, Elf64_Addr baseAddr)
{
    struct stat st;

    Elf64Section::setNull();

    if ((mFd = open(soname.c_str(), O_RDONLY)) < 0) 
    {
        LOGGER_ERROR << "open: " << strerror(errno);
        return false;
    }

    if (fstat(mFd, &st) < 0) 
    {
        LOGGER_ERROR << "fstat: " << strerror(errno);
        return false;
    }

    pMmap = static_cast<uint8_t*>(mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, mFd, 0));
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

    auto pDyn = std::dynamic_pointer_cast<Elf64DynsymSection>(mSecTab[SHT_DYNSYM]);
    if (pDyn == nullptr)
        return false;

    pDyn->insertSoname(soname);

    Elf64_Shdr *sHdr = (Elf64_Shdr*)(pMmap + eHdr->e_shoff);
    int shnum = eHdr->e_shnum;

    Elf64_Shdr *sStrtab = &sHdr[eHdr->e_shstrndx];
    const char *const pStrtab = (char *)pMmap + sStrtab->sh_offset;

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

        if (sHdr[i].sh_type < MAX_SECTIONS && 
            mSecTab[sHdr[i].sh_type] != nullptr)
        {
            mSecTab[sHdr[i].sh_type]->pushSection(pMmap, section, baseAddr);
        }
    }

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
        
        if (sHdr[i].sh_type < MAX_SECTIONS && 
            mSecTab[sHdr[i].sh_type] != nullptr)
        {
            mSecTab[sHdr[i].sh_type]->pushSection(pMmap, section, baseAddr);
        }
    }

    return true;
}

char *Elf64Section::pDynstr = nullptr;

void Elf64Section::setNull()
{
    pDynstr = nullptr;
}

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

void Elf64DynsymSection::pushSection(uint8_t *pMmap, 
                                     Section &sec, Elf64_Addr baseAddr)
{
    auto total_syms = sec.section_size / sizeof(Elf64_Sym);
    auto syms_data = (Elf64_Sym*)(pMmap + sec.section_offset);

    auto symTab = symTabs.find(soname);
    if (symTab == symTabs.end())
        return;

    Symbol symbol;
    for (int i = 0; i < total_syms; ++i) {
        if (sec.section_type != SHT_DYNSYM) continue;
        symbol.symbol_num       = i;
        symbol.symbol_value     = syms_data[i].st_value;
        symbol.symbol_size      = syms_data[i].st_size;
        symbol.symbol_type      = getSymbolType(syms_data[i].st_info);
        symbol.symbol_bind      = getSymbolBind(syms_data[i].st_info);
        symbol.symbol_visibility= getSymbolVisibility(syms_data[i].st_other);
        symbol.symbol_index     = getSymbolIndex(syms_data[i].st_shndx);
        symbol.symbol_section   = sec.section_name;  

        if (pDynstr == nullptr) return;
        
        symbol.symbol_name = std::string(pDynstr + syms_data[i].st_name);
        symTab->second.insert(std::pair<std::string, long>(symbol.symbol_name, 
                                                    baseAddr+symbol.symbol_value));
    }
}

void Elf64DynsymSection::insertSoname(const std::string &soname_)
{
    auto symTab = symTabs.find(soname_);
    if (symTab != symTabs.end())
        return;

    soname = soname_;
    symTabs.insert(std::pair<std::string, SymTab>(soname_, SymTab()));
}

void Elf64DynsymSection::clearAllSyms()
{
    symTabs.clear();
}

long Elf64Wrapper::getSym(const std::string &soname, 
                          const std::string &symname)
{
    auto pDyn = std::dynamic_pointer_cast<Elf64DynsymSection>(mSecTab[SHT_DYNSYM]);
    if (pDyn != nullptr)
    {
        return pDyn->getSym(soname, symname);
    }

    return 0;
}

void Elf64Wrapper::clearAllSyms()
{
    auto pDyn = std::dynamic_pointer_cast<Elf64DynsymSection>(mSecTab[SHT_DYNSYM]);
    if (pDyn != nullptr)
    {
        return pDyn->clearAllSyms();
    }
}

long Elf64DynsymSection::getSym(const std::string &soname, 
                                const std::string &symname)
{
    SymTabs::iterator its;
    SymTab::iterator it;
    if ((its = symTabs.find(soname)) != symTabs.end())
    {
        if ((it = its->second.find(symname)) != its->second.end())
            return it->second;
    }

    return 0;
}

void Elf64StrtabSection::pushSection(uint8_t *pMmap, Section &sec, Elf64_Addr)
{
    if (sec.section_name == ".dynstr")
        pDynstr = (char *)pMmap + sec.section_offset;
}