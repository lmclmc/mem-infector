#ifndef ELFOPT_H_
#define ELFOPT_H_

#include "elf_section.h"

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