/*
This file is part of BitPunch
Copyright (C) 2015 Frantisek Uhrecky <frantisek.uhrecky[what here]gmail.com>>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <bitpunch/config.h>
#include <bitpunch/bitpunch.h>

#ifdef BPU_CONF_MECS_HYBRID
#include <stdint.h>

#include <bitpunch/math/gf2types.h>

#define BPU_HASH_LEN 64

int BPU_KeyExchangeMecs(const BPU_T_Mecs_Ctx *ctx1, const BPU_T_Mecs_Ctx *ctx2);

#endif // BPU_CONF_MECS_HYBRID


