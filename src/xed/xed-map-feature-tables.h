/// @file xed-map-feature-tables.h

// This file was automatically generated.
// Do not edit this file.

#if !defined(XED_MAP_FEATURE_TABLES_H)
# define XED_MAP_FEATURE_TABLES_H
/*BEGIN_LEGAL

Copyright (c) 2021 Intel Corporation

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
  
END_LEGAL */
#include "xed-internal-header.h"
#include "xed-map-info.h"
static XED_INLINE xed_bool_t xed_ild_has_modrm_legacy(xed_uint_t m)
{
   /* [2, 2, 1, 1, 1, 0, 0, 0, 0, 0, 0] */
   const xed_uint64_t data_const = 0x15aULL;
   return (xed_bool_t)((data_const >> (2*m)) & 3);
}
static XED_INLINE xed_bool_t xed_ild_has_disp_legacy(xed_uint_t m)
{
   /* [2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0] */
   const xed_uint64_t data_const = 0xaULL;
   return (xed_bool_t)((data_const >> (2*m)) & 3);
}
static XED_INLINE xed_bool_t xed_ild_has_imm_legacy(xed_uint_t m)
{
   /* [7, 7, 0, 1, 1, 0, 0, 0, 0, 0, 0] */
   const xed_uint64_t data_const = 0x11077ULL;
   return (xed_bool_t)((data_const >> (4*m)) & 15);
}
static XED_INLINE xed_bool_t xed_ild_has_modrm_vex(xed_uint_t m)
{
   /* [0, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0] */
   const xed_uint64_t data_const = 0x58ULL;
   return (xed_bool_t)((data_const >> (2*m)) & 3);
}
static XED_INLINE xed_bool_t xed_ild_has_disp_vex(xed_uint_t m)
{
   /* [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] */
   return 0;
   (void)m;
}
static XED_INLINE xed_bool_t xed_ild_has_imm_vex(xed_uint_t m)
{
   /* [0, 7, 0, 1, 0, 0, 0, 0, 0, 0, 0] */
   const xed_uint64_t data_const = 0x1070ULL;
   return (xed_bool_t)((data_const >> (4*m)) & 15);
}
static XED_INLINE xed_bool_t xed_ild_has_modrm_evex(xed_uint_t m)
{
   /* [0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0] */
   const xed_uint64_t data_const = 0x1454ULL;
   return (xed_bool_t)((data_const >> (2*m)) & 3);
}
static XED_INLINE xed_bool_t xed_ild_has_disp_evex(xed_uint_t m)
{
   /* [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] */
   return 0;
   (void)m;
}
static XED_INLINE xed_bool_t xed_ild_has_imm_evex(xed_uint_t m)
{
   /* [0, 7, 0, 1, 0, 0, 0, 0, 0, 0, 0] */
   const xed_uint64_t data_const = 0x1070ULL;
   return (xed_bool_t)((data_const >> (4*m)) & 15);
}
static XED_INLINE xed_bool_t xed_ild_has_modrm_xop(xed_uint_t m)
{
   /* [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1] */
   const xed_uint64_t data_const = 0x150000ULL;
   return (xed_bool_t)((data_const >> (2*m)) & 3);
}
static XED_INLINE xed_bool_t xed_ild_has_disp_xop(xed_uint_t m)
{
   /* [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] */
   return 0;
   (void)m;
}
static XED_INLINE xed_bool_t xed_ild_has_imm_xop(xed_uint_t m)
{
   /* [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 4] */
   const xed_uint64_t data_const = 0x40100000000ULL;
   return (xed_bool_t)((data_const >> (4*m)) & 15);
}
static XED_INLINE xed_bool_t xed_ild_has_modrm_knc(xed_uint_t m)
{
   /* [0] */
   return 0;
   (void)m;
}
static XED_INLINE xed_bool_t xed_ild_has_disp_knc(xed_uint_t m)
{
   /* [0] */
   return 0;
   (void)m;
}
static XED_INLINE xed_bool_t xed_ild_has_imm_knc(xed_uint_t m)
{
   /* [0] */
   return 0;
   (void)m;
}
static XED_INLINE xed_bool_t xed_ild_has_modrm(xed_uint_t vv, xed_uint_t m)
{
   const xed_uint64_t data_const[5] = {
   /* [2, 2, 1, 1, 1, 0, 0, 0, 0, 0, 0] legacy */
    0x15aULL,
   /* [0, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0] vex */
    0x58ULL,
   /* [0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0] evex */
    0x1454ULL,
   /* [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1] xop */
    0x150000ULL,
   /* [0] knc */
    0x0ULL,
   };
   xed_assert(vv < 5);
   return (xed_bool_t)((data_const[vv] >> (2*m)) & 3);
}
static XED_INLINE xed_bool_t xed_ild_has_disp(xed_uint_t vv, xed_uint_t m)
{
   const xed_uint64_t data_const[5] = {
   /* [2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0] legacy */
    0xaULL,
   /* [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] vex */
    0x0ULL,
   /* [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] evex */
    0x0ULL,
   /* [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] xop */
    0x0ULL,
   /* [0] knc */
    0x0ULL,
   };
   xed_assert(vv < 5);
   return (xed_bool_t)((data_const[vv] >> (2*m)) & 3);
}
static XED_INLINE xed_bool_t xed_ild_has_imm(xed_uint_t vv, xed_uint_t m)
{
   const xed_uint64_t data_const[5] = {
   /* [7, 7, 0, 1, 1, 0, 0, 0, 0, 0, 0] legacy */
    0x11077ULL,
   /* [0, 7, 0, 1, 0, 0, 0, 0, 0, 0, 0] vex */
    0x1070ULL,
   /* [0, 7, 0, 1, 0, 0, 0, 0, 0, 0, 0] evex */
    0x1070ULL,
   /* [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 4] xop */
    0x40100000000ULL,
   /* [0] knc */
    0x0ULL,
   };
   xed_assert(vv < 5);
   return (xed_bool_t)((data_const[vv] >> (4*m)) & 15);
}
static XED_INLINE xed_bool_t xed_ild_map_valid_legacy(xed_uint_t m)
{
   /* [1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0] */
   const xed_uint64_t data_const = 0x1fULL;
   return (xed_bool_t)((data_const >> m) & 1);
}
static XED_INLINE xed_bool_t xed_ild_map_valid_vex(xed_uint_t m)
{
   /* [0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0] */
   const xed_uint64_t data_const = 0xeULL;
   return (xed_bool_t)((data_const >> m) & 1);
}
static XED_INLINE xed_bool_t xed_ild_map_valid_evex(xed_uint_t m)
{
   /* [0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0] */
   const xed_uint64_t data_const = 0x6eULL;
   return (xed_bool_t)((data_const >> m) & 1);
}
static XED_INLINE xed_bool_t xed_ild_map_valid_xop(xed_uint_t m)
{
   /* [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1] */
   const xed_uint64_t data_const = 0x700ULL;
   return (xed_bool_t)((data_const >> m) & 1);
}
static XED_INLINE xed_bool_t xed_ild_map_valid_knc(xed_uint_t m)
{
   /* [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] */
   const xed_uint64_t data_const = 0x0ULL;
   return (xed_bool_t)((data_const >> m) & 1);
}
const xed_map_info_t xed_legacy_maps[] = {
{ 0x0F, 1, 0x38, 2, 2 },
{ 0x0F, 1, 0x3A, 3, 2 },
{ 0x0F, 1, 0x0F, 4, -1 },
{ 0x0F, 0, 0, 1, 1 },
};
#endif