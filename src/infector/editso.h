#ifndef EDITSO_H_
#define EDITSO_H_

#include <iostream>

class EditSo
{
public:
    EditSo() = default;
    ~EditSo() = default;

    bool replaceSoDynsym(const std::string &old_name,
                         const std::string &new_name,
                         const std::string &soname,
                         const std::string &output_soname,
                         uint32_t shift2 = 0xf);
};

#endif