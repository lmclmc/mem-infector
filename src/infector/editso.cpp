#include "editso.h"
#include "elfopt.h"
#include "util/single.hpp"
#include "log/log.h"

using namespace lmc;

bool EditSo::replaceSoDynsym(const std::string &old_name,
                             const std::string &new_name,
                             const std::string &soname,
                             const std::string &output_soname)
{
    Elf64Wrapper *pElf = TypeSingle<Elf64Wrapper>::getInstance();
    if (!pElf->loadSo(soname, 0))
    {
        LOGGER_ERROR << " open " << soname << " error";
        return false;
    }
    LOGGER_INFO << LogFormat::addr << pElf->getSectionAddr(soname, ".gnu.hash");
    LOGGER_INFO << LogFormat::addr << pElf->getSectionAddr(soname, ".dynsym");
}