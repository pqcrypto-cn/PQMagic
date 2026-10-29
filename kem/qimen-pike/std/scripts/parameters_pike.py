#!/usr/bin/env python3
from sage.all import *
proof.all(False)  # faster

import re
for l in open('pike_parameters.txt'):
    for k in ('lvl', 'p', 'B'):
        m = re.search(rf'^\s*{k}\s*=\s*([x0-9a-f]+)', l)
        if m:
            v = ZZ(m.groups()[0], 0)
            globals()[k] = v

L = {l for l,_ in (p**2 - 1).factor(limit=B+1) if l <= B}
assert 2 in L
L.remove(2)
f = (p+1).valuation(2)
if (p-1).valuation(2) > f:
    raise NotImplementedError('2-power torsion is on twist')
Lpls = {l for l in L if (p+1).valuation(l) >= (p-1).valuation(l)}
Lmin = L - Lpls
Lpls, Lmin = map(sorted, (Lpls, Lmin))
Epls = [(p+1).valuation(l) for l in Lpls]
Emin = [(p-1).valuation(l) for l in Lmin]
Tpls = prod(l**e for l,e in zip(Lpls,Epls))
Tmin = prod(l**e for l,e in zip(Lmin,Emin))

Dchall = prod(l**(p+1).valuation(l) for l in (2,3))

__all__ = ['lvl', 'p', 'B', 'f', 'Tpls', 'Tmin', 'Dchall']

