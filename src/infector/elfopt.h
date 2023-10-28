#ifndef ELFOPT_H_
#define ELFOPT_H_

#include <string>
#include <map>
#include <memory>
#include <list>
#include <functional>
#include <elf.h>

typedef struct {
    int section_index = 0; 
    std::intptr_t section_offset, section_addr;
    std::string section_name;
    int section_type; 
    int section_size, section_ent_size, section_addr_align;
} Section;

typedef struct {
    uint16_t symbol_index = 0;
    std::string symbol_index_str = "";
    std::intptr_t symbol_value = 0;
    uint32_t symbol_idx = 0, symbol_size = 0;
    unsigned char symbol_info = 0, symbol_other = 0;
    std::string symbol_type = "", symbol_bind = "";
    std::string symbol_visibility = "";
    uint64_t symbol_name_addr = 0;
    std::string symbol_name = "";
    std::string symbol_section = "";  
    std::map<int32_t, Elf64_Rela>  symbol_rela_table;
} Symbol;

typedef struct {
    bool need;
    uint32_t offset;
    std::string name;
    uint64_t gnuver[2];
} GnuVer;

class Elf64Section
{
    friend class Elf64Wrapper;
    using SymTab = std::list<Symbol>;
    using GnuVerTab = std::list<GnuVer>;
public:
    void pushSection(uint8_t *pMap, Section &section, 
                     Elf64_Addr baseAddr, uint64_t userdata = 0)
    {
        sectionSize = section.section_size;
        sectionAddr = section.section_addr;
        pushSectionS(pMap, section, baseAddr, userdata);
    }

    Elf64_Addr getSectionAddr()
    {
        return sectionAddr;
    }

    uint32_t getSectionSize()
    {
        return sectionSize;
    }

    SymTab &getSymTab();

    GnuVerTab &getGnuVerTab();

protected:
    virtual void pushSectionS(uint8_t *, Section &section, 
                              Elf64_Addr, uint64_t){}

protected:
    uint32_t sectionSize;
    Elf64_Addr sectionAddr;
    static SymTab symTab;
    static GnuVerTab gnuVersionTab;
};

class Elf64DynsymSection final: public Elf64Section
{
public:
    long getSymAddr(const std::string &);

protected:
    void pushSectionS(uint8_t *, Section &, Elf64_Addr, uint64_t) override;

private:
    std::string getSymbolType(uint8_t &);
    std::string getSymbolBind(uint8_t &);
    std::string getSymbolVisibility(uint8_t &);
    std::string getSymbolIndex(uint16_t &); 
};

class Elf64RelaDynSectoin final : public Elf64Section
{
protected:
    void pushSectionS(uint8_t *, Section &, Elf64_Addr, uint64_t) override;

};

class Elf64GnuVerSectoin final : public Elf64Section
{
protected:
    void pushSectionS(uint8_t *, Section &, Elf64_Addr, uint64_t) override;
};

class Elf64SectionWrapper
{
    using SecTab = std::map<std::string, std::shared_ptr<Elf64Section>>;
public:
    Elf64SectionWrapper();
    SecTab &getSecTab();

private:
    SecTab mSecTab;
};

class Elf64Wrapper
{
public:
    Elf64Wrapper() : pMmap(nullptr),
                     mFd(0){}
    bool loadSo(const std::string &, Elf64_Addr);

    Elf64_Addr getSymAddr(const std::string &, const std::string &);

    Elf64_Addr getSectionAddr(const std::string &, const std::string &);

    uint32_t getSectionSize(const std::string &, const std::string &);

    Elf64Section::SymTab &getDynsymTab(const std::string &);

    Elf64Section::GnuVerTab &getGnuVerTab(const std::string &);

    void clearAllSyms();

private:
    uint8_t *pMmap;
    int mFd;

    std::map<std::string, std::shared_ptr<Elf64SectionWrapper>> mSecWrapperTab;
};
#endif