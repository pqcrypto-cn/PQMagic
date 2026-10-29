#!/usr/bin/env sage
proof.all(False)  # faster

from parameters import p

num_entries = 20  # as specified in paper

set_random_seed(0)

################################################################

Fp2.<i> = GF((p,2), modulus=[1,0,1])

nqr_table = []
while len(nqr_table) < num_entries:
    elt = Fp2.random_element()
    if not elt.is_square():
        nqr_table.append(elt)

z_nqr_table = []
while len(z_nqr_table) < num_entries:
    elt = Fp2.random_element()
    if elt.is_square() and not (elt-1).is_square():
        z_nqr_table.append(elt)

################################################################

from cformat import Object, ObjectFormatter

# Use modarith unsaturated radix parameters
from modarith_params import get_modarith_params
_ma = get_modarith_params(p)
_ma_nlimbs = _ma['nlimbs']
_ma_radix = _ma['radix']
_ma_R = 2**(_ma_nlimbs * _ma_radix)

def field2limbs(el):
    l = _ma_nlimbs
    el = Fp2(el)
    mask = (1 << _ma_radix) - 1
    el = [_ma_R * c for c in el]  # convert to Montgomery form
    vs = [[(int(c) >> _ma_radix*i) & mask for i in range(l)] for c in el]
    return vs

objs = ObjectFormatter([
        Object('fp2_t[]', 'NQR_TABLE', list(map(field2limbs, nqr_table))),
        Object('fp2_t[]', 'Z_NQR_TABLE', list(map(field2limbs, z_nqr_table))),
    ])

with open('include/gf_constants.h','w') as hfile:
    with open('gf_constants.c','w') as cfile:

        print(f'#include <fp2.h>', file=hfile)

        print(f'#include <stddef.h>', file=cfile)
        print(f'#include <stdint.h>', file=cfile)
        print(f'#include <tutil.h>', file=cfile)
        print(f'#include <fp2.h>', file=cfile)

        objs.header(file=hfile)
        objs.implementation(file=cfile)

