#include "editso.h"
#include "elf/elfopt.h"
#include "util/single.hpp"
#include "log/log.h"

#include <list>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>

using namespace lmc;

typedef struct {
        //const Sym* dyn_sym;
        uint32_t nbuckets;
        uint32_t first_sym_ndx;
        uint32_t maskwords_bm;
        uint32_t shift2;
        uint64_t *bloom;
        uint32_t *buckets;
        uint32_t *hash_val;
} obj_state_t;

static uint32_t elf_new_hash(const char* name)
{
    if (!name)
        return 0;

    const unsigned char *n = (const unsigned char *)name;
    uint32_t h = 5381;
    for (unsigned char c = *n; c != '\0'; c = *++n)
            h = h*33 + c;

    return h;
}

static bool calObjState(obj_state_t *obj_state, 
                        std::list<Symbol> &dynsymTab, 
                        uint32_t nbuckets, uint32_t ndx, 
                        uint32_t maskwords_bm, uint32_t shift2)
{
    obj_state->nbuckets = nbuckets;
    obj_state->first_sym_ndx = ndx;
    obj_state->maskwords_bm = maskwords_bm;
    obj_state->shift2 = shift2;
 
    obj_state->bloom = (uint64_t *)calloc(obj_state->maskwords_bm, sizeof(uint64_t));
    obj_state->buckets = (uint32_t *)calloc(obj_state->nbuckets, sizeof(uint32_t));
    obj_state->hash_val = (uint32_t *)calloc(dynsymTab.size(), sizeof(uint32_t));

    uint32_t c = sizeof(uint64_t) * 8;
    uint32_t countIdx = ndx;
    for (auto it = dynsymTab.begin(); it != dynsymTab.end(); it++)
    {
        uint32_t h1 = elf_new_hash((const char *)it->symbol_name.c_str());
        uint32_t h2 = h1 >> obj_state->shift2;

        uint32_t n = (h1 / c) % obj_state->maskwords_bm;
        uint64_t bitmask = ((uint64_t)1 << (h1 % c)) | 
                           ((uint64_t)1 << (h2 % c));

        obj_state->bloom[n] |= bitmask;

        size_t bucket_idx = h1 % obj_state->nbuckets;
        n = obj_state->buckets[bucket_idx];
        if (n == 0)
            obj_state->buckets[bucket_idx] = countIdx;

        auto it_bk = it;
        uint32_t lsb = 0;
        if (++it_bk != dynsymTab.end())
        {
            uint32_t h11 = elf_new_hash((const char *)
                           (it_bk)->symbol_name.c_str()) % obj_state->nbuckets;
            lsb = (h1 % obj_state->nbuckets) != h11;
        } else
        {
            lsb = 1;
        }

        uint32_t h_val = (h1 & ~1) | lsb;

        obj_state->hash_val[countIdx - ndx] = h_val;
        countIdx++;
    }
}

static void writeObjstate(int fd, obj_state_t *obj_state, uint32_t defcount)
{
    size_t bloom_size = obj_state->maskwords_bm * sizeof(uint64_t);
    size_t bucket_size = obj_state->nbuckets * sizeof(uint32_t);
    size_t val_size = defcount * sizeof(uint32_t);
    size_t obj_size = 4 * 4 + bloom_size + bucket_size + val_size;

    unsigned char* pObj = (unsigned char*)obj_state;
    size_t p_chg_size = 16;
    for (size_t i = 0; i < obj_size; i++) {
        if (i == 16) {
            pObj = (unsigned char*)obj_state->bloom;
        } else if (i == 16 + bloom_size) {
            pObj = (unsigned char*)obj_state->buckets;
        } else if (i == 16 + bloom_size+bucket_size) {
            pObj = (unsigned char*)obj_state->hash_val;
        }

        write(fd, pObj++, 1);
    }
}

static void writeDynsym(int fd, Elf64_Addr baseAddr,
                        std::list<Symbol> &dynsymTab)
{
    lseek(fd, baseAddr, SEEK_SET);
    Elf64_Sym sym;
    for (auto &d : dynsymTab)
    {
        sym.st_name = d.symbol_name_addr;
        sym.st_info = d.symbol_info;
        sym.st_other = d.symbol_other;
        sym.st_shndx = d.symbol_index;
        sym.st_size = d.symbol_size;
        sym.st_value = d.symbol_value;
        
        write(fd, &sym, sizeof(Elf64_Sym));
    }
}

static void writeGnuVerStr(int fd, Elf64_Addr dynstrAddr, 
                           Elf64_Addr gnuverAddr, std::list<GnuVer> &gnuverTab)
{
    for (auto &g : gnuverTab)
    {
        lseek(fd, dynstrAddr + g.offset, SEEK_SET);
        write(fd, g.name.c_str(), g.name.size());
        write(fd, "\0", 1);
    }

    lseek(fd, gnuverAddr, SEEK_SET);
    for (auto &g : gnuverTab)
    {
        write(fd, &g.gnuver, sizeof(GnuVer::gnuver));
    }
}

static void writeDynStr(int fd, Elf64_Addr baseAddr,
                        std::list<Symbol> &dynsymTab)
{
    Elf64_Sym sym;
    for (auto &d : dynsymTab)
    {
        lseek(fd, baseAddr + d.symbol_name_addr, SEEK_SET);
        write(fd, d.symbol_name.c_str(), d.symbol_name.size());
        write(fd, "\0", 1);
    }
}

static void updateRelasym(int fd, uint64_t relaBaseOffset, 
                          std::list<Symbol> &dynsymTab, int ndx)
{
    uint64_t idx = ndx;
    int count = 0;
    for (auto &d : dynsymTab)
    {
        for (auto &m : d.symbol_rela_table)
        {
            m.second.r_info =  (idx << 32) | (m.second.r_info & 0xffffffff);
            lseek(fd, relaBaseOffset + sizeof(Elf64_Rela) * m.first, SEEK_SET);
            write(fd, &m.second, sizeof(Elf64_Rela));
        }

        idx++;
    }
}

static std::string randStr()
{
    static int count = 0;
    return std::to_string(count++);
}

bool EditSo::confuse(const std::string &input_soname,
                     const std::string &output_soname,
                     const std::set<std::string> &filter)
{
    Elf64Wrapper *pElf = TypeSingle<Elf64Wrapper>::getInstance();
    if (!pElf->loadSo(input_soname, 0))
    {
        LOGGER_ERROR << " open " << input_soname << " error";
        return false;
    }

    std::list<Symbol> dynUndefSymTab;
    auto &dynsymTab  = pElf->getDynsymTab(input_soname);
    auto &gnuverTab  = pElf->getGnuVerTab(input_soname);

    uint64_t addrcount = 0;
    for (auto it = dynsymTab.begin();;)
    {
        if (it->symbol_name.empty() || it->symbol_index == SHN_UNDEF)
        {
            it->symbol_name_addr = addrcount;
            addrcount = addrcount + it->symbol_name.size() + 1;
            dynUndefSymTab.emplace_back(*it);
            it = dynsymTab.erase(it);
        } else 
        {
            it++;
            if (it == dynsymTab.end())
                break;
            
            if (filter.find(it->symbol_name) == filter.end())
                it->symbol_name = randStr();

            it->symbol_name_addr = addrcount;
            addrcount = addrcount + it->symbol_name.size() + 1;
        }
    }

    for (auto &g : gnuverTab)
    {
        if (g.need)
        {
            ((Elf64_Verneed *)&g.gnuver)->vn_file = addrcount;
        } else {
            ((Elf64_Vernaux *)&g.gnuver)->vna_name = addrcount;
        }
        g.offset = addrcount;
        addrcount = addrcount + g.name.size() + 1;
    }

    int mInputFd = 0;
    if ((mInputFd = open(input_soname.c_str(), O_RDONLY)) < 0) 
    {
        LOGGER_ERROR << "open: " << input_soname << strerror(errno);
        return false;
    }

    struct stat inputSt;
    if (fstat(mInputFd, &inputSt) < 0) 
    {
        LOGGER_ERROR << "fstat: " << strerror(errno);
        return false;
    }

    uint8_t *pInputMmap = static_cast<uint8_t*>(mmap(NULL, inputSt.st_size, 
                                                      PROT_READ, MAP_PRIVATE, 
                                                      mInputFd, 0));
    if (pInputMmap == MAP_FAILED) 
    {
        LOGGER_ERROR << "mmap: " << strerror(errno);
        return false;
    }

    int mOutputFd = 0;
    if ((mOutputFd = open(output_soname.c_str(), O_CREAT | O_RDWR)) < 0) 
    {
        LOGGER_ERROR << "open: " << output_soname << strerror(errno);
        return false;
    }

    uint64_t gnuhashAddr = pElf->getSectionAddr(input_soname, ".gnu.hash");
    if (!gnuhashAddr)
    {
        LOGGER_ERROR << "gnu hash section not exist";
        return false;
    }

    uint64_t gnuhashMapAddr = (uint64_t)pInputMmap +gnuhashAddr;
    uint32_t nbuckets = *(uint64_t *)gnuhashMapAddr & 0xffffffff;
    uint32_t undefCount = *(uint64_t *)gnuhashMapAddr >> 32;
    uint32_t maskwords_bm = *((uint64_t *)gnuhashMapAddr+1) & 0xffffffff;
    uint32_t shift2 = *((uint64_t *)gnuhashMapAddr+1) >> 32;
    dynsymTab.sort([=](const Symbol &s1, const Symbol &s2){
        uint32_t sh1 = elf_new_hash((const char *)s1.symbol_name.c_str())
                                                  % nbuckets;
        uint32_t sh2 = elf_new_hash((const char *)s2.symbol_name.c_str())
                                                  % nbuckets;
        return sh1 < sh2;
    });

    write(mOutputFd, pInputMmap, gnuhashAddr);
    obj_state_t obj_state;
    calObjState(&obj_state, dynsymTab, nbuckets, undefCount, 
                maskwords_bm, shift2);
    writeObjstate(mOutputFd, &obj_state, dynsymTab.size());

    uint64_t dynsymAddr = pElf->getSectionAddr(input_soname, ".dynsym");
    writeDynsym(mOutputFd, dynsymAddr, dynUndefSymTab);
    writeDynsym(mOutputFd, dynsymAddr + dynUndefSymTab.size() * 0x18, dynsymTab);

    uint64_t dynstrAddr = pElf->getSectionAddr(input_soname, ".dynstr");
    uint32_t dynstrSize = pElf->getSectionSize(input_soname, ".dynstr");
    write(mOutputFd, pInputMmap + dynstrAddr, inputSt.st_size - dynstrAddr);

    unsigned char buffer[1024 * 1024] = {0};
    lseek(mOutputFd, dynstrAddr, SEEK_SET);
    write(mOutputFd, buffer, dynstrSize);

    writeDynStr(mOutputFd, dynstrAddr, dynUndefSymTab);
    writeDynStr(mOutputFd, dynstrAddr, dynsymTab);

    uint32_t gnuverAddr = pElf->getSectionAddr(input_soname, ".gnu.version_r");
    writeGnuVerStr(mOutputFd, dynstrAddr, gnuverAddr, gnuverTab);
    
    uint64_t reladynAddr = pElf->getSectionAddr(input_soname, ".rela.dyn");
    updateRelasym(mOutputFd, reladynAddr, dynsymTab, undefCount);
    close(mInputFd);
    close(mOutputFd);
}

bool EditSo::replaceSoDynsym(const std::string &old_name,
                             const std::string &new_name,
                             const std::string &input_soname,
                             const std::string &output_soname)
{
    Elf64Wrapper *pElf = TypeSingle<Elf64Wrapper>::getInstance();
    if (!pElf->loadSo(input_soname, 0))
    {
        LOGGER_ERROR << " open " << input_soname << " error";
        return false;
    }

    auto &dynsymTab  = pElf->getDynsymTab(input_soname);
    auto iter = dynsymTab.end();
    for (auto it = dynsymTab.begin(); it != dynsymTab.end();)
    {
        if (old_name == it->symbol_name)
            iter = it;

        if (it->symbol_name.empty() || it->symbol_index == SHN_UNDEF)
        {
            it = dynsymTab.erase(it);
        } else 
        {
            it++;
        }
    }

    if (iter == dynsymTab.end())
    {
        LOGGER_ERROR << old_name << " not found";
        return false;
    }

    iter->symbol_name = new_name;

    int mInputFd = 0;
    if ((mInputFd = open(input_soname.c_str(), O_RDONLY)) < 0) 
    {
        LOGGER_ERROR << "open: " << input_soname << strerror(errno);
        return false;
    }

    struct stat inputSt;
    if (fstat(mInputFd, &inputSt) < 0) 
    {
        LOGGER_ERROR << "fstat: " << strerror(errno);
        return false;
    }

    uint8_t *pInputMmap = static_cast<uint8_t*>(mmap(NULL, inputSt.st_size, 
                                                      PROT_READ, MAP_PRIVATE, 
                                                      mInputFd, 0));
    if (pInputMmap == MAP_FAILED) 
    {
        LOGGER_ERROR << "mmap: " << strerror(errno);
        return false;
    }

    int mOutputFd = 0;
    if ((mOutputFd = open(output_soname.c_str(), O_CREAT | O_RDWR)) < 0) 
    {
        LOGGER_ERROR << "open: " << output_soname << strerror(errno);
        return false;
    }

    uint64_t gnuhashAddr = pElf->getSectionAddr(input_soname, ".gnu.hash");
    if (!gnuhashAddr)
    {
        LOGGER_ERROR << "gnu hash section not exist";
        return false;
    }

    uint64_t gnuhashMapAddr = (uint64_t)pInputMmap +gnuhashAddr;
    uint32_t nbuckets = *(uint64_t *)gnuhashMapAddr & 0xffffffff;
    uint32_t undefCount = *(uint64_t *)gnuhashMapAddr >> 32;
    uint32_t maskwords_bm = *((uint64_t *)gnuhashMapAddr+1) & 0xffffffff;
    uint32_t shift2 = *((uint64_t *)gnuhashMapAddr+1) >> 32;
    dynsymTab.sort([=](const Symbol &s1, const Symbol &s2){
        uint32_t sh1 = elf_new_hash((const char *)s1.symbol_name.c_str())
                                                  % nbuckets;
        uint32_t sh2 = elf_new_hash((const char *)s2.symbol_name.c_str())
                                                  % nbuckets;
        return sh1 < sh2;
    });

    write(mOutputFd, pInputMmap, gnuhashAddr);
    obj_state_t obj_state;
    calObjState(&obj_state, dynsymTab, nbuckets, undefCount, 
                maskwords_bm, shift2);
    writeObjstate(mOutputFd, &obj_state, dynsymTab.size());

    uint64_t dynsymAddr = pElf->getSectionAddr(input_soname, ".dynsym");
    write(mOutputFd, pInputMmap + dynsymAddr, undefCount * 0x18);
    writeDynsym(mOutputFd, dynsymAddr + undefCount * 0x18, dynsymTab);

    uint64_t dynstrAddr = pElf->getSectionAddr(input_soname, ".dynstr");
    write(mOutputFd, pInputMmap + dynstrAddr, inputSt.st_size - dynstrAddr);
    lseek(mOutputFd, dynstrAddr + iter->symbol_name_addr, SEEK_SET);
    write(mOutputFd, new_name.c_str(), new_name.size());

    uint64_t reladynAddr = pElf->getSectionAddr(input_soname, ".rela.dyn");
    updateRelasym(mOutputFd, reladynAddr, dynsymTab, undefCount);
    close(mInputFd);
    close(mOutputFd);
    return true;
}