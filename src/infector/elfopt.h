#ifndef ELFOPT_H_
#define ELFOPT_H_

#include <string>
#include <map>
#include <memory>
#include <elf.h>

typedef struct {
    int section_index = 0; 
    std::intptr_t section_offset, section_addr;
    std::string section_name;
    int section_type; 
    int section_size, section_ent_size, section_addr_align;
} Section;

typedef struct {
    std::string symbol_index;
    std::intptr_t symbol_value;
    int symbol_num = 0, symbol_size = 0;
    std::string symbol_type, symbol_bind;
    std::string symbol_visibility;
    std::string symbol_name;
    std::string symbol_section;      
} Symbol;

class Elf64Section
{
    friend class Elf64Wrapper;
public:
    virtual void pushSection(uint8_t *, Section &section, Elf64_Addr)
    {
        sectionAddr = section.section_addr;
    }

    uint64_t getSectionAddr()
    {
        return sectionAddr;
    }

protected:
    static char *pDynstr;
    uint64_t sectionAddr;

private:
    static void setNull();
};

class Elf64DynsymSection final: public Elf64Section
{
public:
    using SymTab = std::map<std::string, Symbol>;

    void pushSection(uint8_t *, Section &, Elf64_Addr) override;

    long getSymAddr(const std::string &);

private:
    std::string getSymbolType(uint8_t &);
    std::string getSymbolBind(uint8_t &);
    std::string getSymbolVisibility(uint8_t &);
    std::string getSymbolIndex(uint16_t &);

private:
    SymTab symTab;
};

class Elf64DynstrSection final : public Elf64Section
{
public:
    void pushSection(uint8_t *, Section &, Elf64_Addr) override;
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

    long getSymAddr(const std::string &, const std::string &);

    long getSectionAddr(const std::string &, const std::string &);

    void clearAllSyms();

public:
    uint8_t *pMmap;
    int mFd;

    std::map<std::string, std::shared_ptr<Elf64SectionWrapper>> mSecWrapperTab;
};
#endif