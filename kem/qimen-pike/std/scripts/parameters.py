#!/usr/bin/env python3
from sage.all import *
proof.all(False)  # faster

import re
for l in open('pike_parameters.txt'):
    for k in ('lvl', 'p', 'B', 'ppofactor', 'Cfactor', 'use_cfactor', 'use_twist', 'TORSION_D'):
        m = re.search(rf'^\s*{k}\s*=\s*([x0-9a-f]+)', l)
        if m:
            v = ZZ(m.groups()[0], 0)
            globals()[k] = v

L = {l for l,_ in (p + 1).factor(limit=B+5) if l <= B}
if use_twist == 1 and use_cfactor == 1:
    L.add(Cfactor)
    # L.add((p-1)//Cfactor)
assert 2 in L
L.remove(2)
f = (p+1).valuation(2)
if use_twist == 1 and (p-1).valuation(2) > f:
    raise NotImplementedError('2-power torsion is on twist')
if use_cfactor == 1: expC = (p+1).valuation(Cfactor) if use_twist == 0 else (p-1).valuation(Cfactor)
else: expC = 1
if use_twist == 1 :
    Lpls = {l for l in L if (p+1).valuation(l) >= (p-1).valuation(l)}
else:
    Lpls = {l for l in L}
    
Lmin = L - Lpls
Lpls, Lmin = map(sorted, (Lpls, Lmin))
Epls = [(p+1).valuation(l) for l in Lpls]
Emin = [1, 1]
if use_twist == 1: Emin = [(p-1).valuation(l) for l in Lmin]
Tpls = prod(l**e for l,e in zip(Lpls,Epls))
Tmin = 1
if use_twist == 1: Tmin = prod(l**e for l,e in zip(Lmin,Emin))

Dchall = 2**((p+1).valuation(2))
# prod(l**(p+1).valuation(l) for l in (2))

__all__ = ['lvl', 'p', 'B', 'Cfactor', 'use_cfactor', 'use_twist', 'f', 'expC', 'Tpls', 'Tmin', 'Dchall', 'TORSION_D']

