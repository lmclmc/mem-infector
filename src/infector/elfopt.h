#ifndef ELFOPT_H_
#define ELFOPT_H_

#include <string>
#include <vector>
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
    std::string symbol_type, symbol_bind, symbol_visibility, symbol_name, symbol_section;      
} Symbol;

class Elf64Section
{
    friend class Elf64Wrapper;
public:
    virtual void pushSection(uint8_t *, Section &, Elf64_Addr){}

private:
    static void setNull();

protected:
    static char *pDynstr;
};

class Elf64DynsymSection final: public Elf64Section
{
public:
    using SymTab = std::map<std::string, long>;
    using SymTabs = std::map<std::string, SymTab>;

    void pushSection(uint8_t *, Section &, Elf64_Addr) override;

    long getSym(const std::string &, const std::string &);

    void insertSoname(const std::string &);

    void clearAllSyms();

private:
    std::string getSymbolType(uint8_t &);
    std::string getSymbolBind(uint8_t &);
    std::string getSymbolVisibility(uint8_t &);
    std::string getSymbolIndex(uint16_t &);

private:
    SymTabs symTabs;
    std::string soname;
};

class Elf64StrtabSection final: public Elf64Section
{
public:
    void pushSection(uint8_t *, Section &, Elf64_Addr = 0) override;
};

class Elf64Wrapper
{
public:
    Elf64Wrapper();
    bool loadSo(const std::string &, Elf64_Addr);

    long getSym(const std::string &, const std::string &);

    void clearAllSyms();

private:
    uint8_t *pMmap;
    int mFd;

    std::vector<std::shared_ptr<Elf64Section>> mSecTab;
};
#endif