#!/usr/bin/env sage
proof.all(False)  # faster

from sage.misc.banner import require_version
if not require_version(9, 8, print_message=True):
    exit('')

################################################################

from parameters import p, B, Cfactor, use_cfactor, use_twist, f, Tpls, Tmin, Dchall, TORSION_D

################################################################

Lpls = sorted(set(Tpls.prime_factors()) - {2})
Epls = [Tpls.valuation(l) for l in Lpls]

if use_twist == 1:
    Lmin = sorted([Cfactor, (p-1)//Cfactor])
    Emin = [Tmin.valuation(l) for l in Lmin]
else:
    Lmin = []
    Emin = []

tors2part = (p+1).p_primary_part(2)
if use_cfactor == 1:
    torsCpart = (p+1).p_primary_part(Cfactor) if use_twist == 0 else Cfactor
    tors2Cpart = tors2part * torsCpart
tors2Dpart = (p+1).p_primary_part(2) * TORSION_D
tors2plspart = tors2part * Tpls
torsDplspart = TORSION_D * Tpls
tors2Dplspart = Tpls * tors2Dpart

#defs = {
#        'TORSION_2POWER_BYTES': (int(tors2part).bit_length() + 7) // 8,
#        'TORSION_CPOWER_BYTES': (int(torsCpart).bit_length() + 7) // 8,
#        'TORSION_2DPOWER_BYTES': (int(tors2Dpart).bit_length() + 7) // 8,

#    } if use_cfactor == 1 else {
#        'TORSION_2POWER_BYTES': (int(tors2part).bit_length() + 7) // 8,
#    } 

from cformat import Ibz, Object, ObjectFormatter

if use_twist == 1:
    objs = ObjectFormatter([
        Object('uint64_t', 'TORSION_PLUS_EVEN_POWER', int(f)),
        Object('uint64_t[]', 'TORSION_ODD_PRIMES', Lpls + Lmin[:-1]),
        Object('uint64_t[]', 'TORSION_ODD_POWERS', Epls + Emin[:-1]),
        Object('uint64_t[]', 'TORSION_PLUS_ODD_PRIMES', Lpls),      # TODO deduplicate?
        Object('size_t[]', 'TORSION_PLUS_ODD_POWERS', Epls),        # TODO deduplicate?
        Object('uint64_t[]', 'TORSION_MINUS_ODD_PRIMES', Lmin[:-1]),     # TODO deduplicate?
        Object('size_t[]', 'TORSION_MINUS_ODD_POWERS', Emin[:-1]),       # TODO deduplicate?
        Object('ibz_t', 'CHARACTERISTIC', Ibz(p)),
        Object('ibz_t', 'TORSION_ODD', Ibz(Tpls * Tmin)),
        Object('ibz_t', 'TORSION_MINUS_PRIME', Ibz(Cfactor)),
        Object('ibz_t', 'TORSION_D', Ibz(TORSION_D)),
        Object('ibz_t', 'Pairing_exp', Ibz((p+1)//TORSION_D)),
        Object('ibz_t[]', 'TORSION_ODD_PRIMEPOWERS', [Ibz(l^e) for l,e in (list(zip(Lpls, Epls)) + list(zip(Lmin, Emin)))[:-1]]),
        Object('ibz_t', 'TORSION_ODD_PLUS', Ibz(Tpls)),
        Object('ibz_t', 'TORSION_ODD_MINUS', Ibz(Tmin)),
        Object('ibz_t', 'TORSION_PLUS_2POWER', Ibz(tors2part)),
#        Object('ibz_t', 'TORSION_PLUS_CPOWER', Ibz(torsCpart)),
        Object('ibz_t', 'TORSION_PLUS_D_2POWER', Ibz(tors2Dpart)),
        Object('ibz_t', 'TORSION_PLUS_ODD_2POWER', Ibz(tors2plspart)),
        Object('ibz_t', 'TORSION_PLUS_ODD_D', Ibz(torsDplspart)),
        Object('ibz_t', 'TORSION_PLUS_ODD_D_2POWER', Ibz(tors2Dplspart)),
    ])
elif use_cfactor == 1:
    objs = ObjectFormatter([
        Object('uint64_t', 'TORSION_PLUS_EVEN_POWER', int(f)),
        Object('uint64_t[]', 'TORSION_ODD_PRIMES', Lpls + Lmin),
        Object('uint64_t[]', 'TORSION_ODD_POWERS', Epls + Emin),
        Object('uint64_t[]', 'TORSION_PLUS_ODD_PRIMES', Lpls),      # TODO deduplicate?
        Object('size_t[]', 'TORSION_PLUS_ODD_POWERS', Epls),        # TODO deduplicate?
        # Object('uint64_t[]', 'TORSION_MINUS_ODD_PRIMES', Lmin),     # TODO deduplicate?
        # Object('size_t[]', 'TORSION_MINUS_ODD_POWERS', Emin),       # TODO deduplicate?
        Object('ibz_t', 'CHARACTERISTIC', Ibz(p)),
        Object('ibz_t', 'TORSION_ODD', Ibz(Tpls * Tmin)),
        Object('ibz_t[]', 'TORSION_ODD_PRIMEPOWERS', [Ibz(l^e) for l,e in Tpls.factor()]),
        Object('ibz_t', 'TORSION_ODD_PLUS', Ibz(Tpls)),
        Object('ibz_t', 'TORSION_ODD_MINUS', Ibz(Tmin)),
        Object('ibz_t', 'TORSION_PLUS_2POWER', Ibz(tors2part)),
#        Object('ibz_t', 'TORSION_PLUS_CPOWER', Ibz(torsCpart)),
    ])
else : 
    objs = ObjectFormatter([
        Object('uint64_t', 'TORSION_PLUS_EVEN_POWER', int(f)),
        Object('uint64_t[]', 'TORSION_ODD_PRIMES', Lpls + Lmin),
        Object('uint64_t[]', 'TORSION_ODD_POWERS', Epls + Emin),
        Object('uint64_t[]', 'TORSION_PLUS_ODD_PRIMES', Lpls),      # TODO deduplicate?
        Object('size_t[]', 'TORSION_PLUS_ODD_POWERS', Epls),        # TODO deduplicate?
        # Object('uint64_t[]', 'TORSION_MINUS_ODD_PRIMES', Lmin),     # TODO deduplicate?
        # Object('size_t[]', 'TORSION_MINUS_ODD_POWERS', Emin),       # TODO deduplicate?
        Object('ibz_t', 'CHARACTERISTIC', Ibz(p)),
        Object('ibz_t', 'TORSION_ODD', Ibz(Tpls * Tmin)),
        Object('ibz_t[]', 'TORSION_ODD_PRIMEPOWERS', [Ibz(l^e) for l,e in Tpls.factor()]),
        Object('ibz_t', 'TORSION_ODD_PLUS', Ibz(Tpls)),
        Object('ibz_t', 'TORSION_ODD_MINUS', Ibz(Tmin)),
    ])

with open('include/torsion_constants.h','w') as hfile:
    with open('torsion_constants.c','w') as cfile:
        print(f'#include <intbig.h>', file=hfile)
        print(f'#include <stddef.h>', file=cfile)
        print(f'#include <stdint.h>', file=cfile)
        print(f'#include <torsion_constants.h>', file=cfile)

#        for k,v in defs.items():
#            print(f'#define {k} {v}', file=hfile)

        objs.header(file=hfile)
        objs.implementation(file=cfile)

