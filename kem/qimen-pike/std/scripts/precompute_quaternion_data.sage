#!/usr/bin/env sage
proof.all(False)  # faster

from sage.misc.banner import require_version
if not require_version(9, 8, print_message=True):
    exit('')

################################################################

from parameters import p
num = 7  #TODO how many extra maximal orders to precompute?

################################################################

# Underlying theory:
# - Ibukiyama, On maximal orders of division quaternion algebras with certain optimal embeddings
# - https://ia.cr/2023/106 Lemma 10

from sage.algebras.quatalg.quaternion_algebra import basis_for_quaternion_lattice
bfql = lambda els: basis_for_quaternion_lattice(els, reverse=True)

Quat.<i,j,k> = QuaternionAlgebra(-1, -p)
assert Quat.discriminant() == p         # ramifies correctly

orders = []

q = 1
while len(orders) < num:
    q = next_prime(q)

    if q == 2:
        continue

    Quat2.<ii,jj,kk> = QuaternionAlgebra(-q, -p)
    if Quat2.discriminant() != p:       # ramifies incorrectly
        continue

    x, y = QuadraticForm(QQ, 2, [1,0,p]).solve(q)
    gamma = x + j*y
    assert gamma.reduced_norm() == q
    ims = [Quat(1), i*gamma, j, k*gamma]
    assert ims[1]^2 == -q
    assert ims[2]^2 == -p
    assert ims[1]*ims[2] == ims[3]
    assert ims[2]*ims[1] == -ims[3]
    # (1,ii,jj,kk)->ims is an isomorphism Quat2->Quat

    r = min(map(ZZ, Mod(-p, 4*q).sqrt(all=True)))

    if q % 4 == 3:
        bas2 = [
                Quat2(1),
                (1 + ii) / 2,
                jj * (1 + ii) / 2,
                (r + jj) * ii / q,
            ]
    else:
        bas2 = [
                Quat2(1),
                ii,
                (1 + jj) / 2,
                (r + jj) * ii / 2 / q,
            ]
    O2 = Quat2.quaternion_order(bas2)
    assert O2.discriminant() == p       # is maximal

    bas = [sum(c*im for c,im in zip(el,ims)) for el in bas2]
    bas = bfql(bas)
    O = Quat.quaternion_order(bas)
    assert O.discriminant() == p        # is maximal
    assert j in O                       # p-extremal

    mat = matrix(map(list, bas))
#    print(f'{q = }\nsqrt(-q) = {ims[1]}\n    {(chr(10)+"    ").join(map(str,bas))}', file=sys.stderr)
    assert mat[0] == vector((1,0,0,0))
    orders.append((q, ims[1], mat))

################################################################

gram = matrix(ZZ, [
    [((gi+gj).reduced_norm() - gi.reduced_norm() - gj.reduced_norm()) / 2
        for gi in Quat.basis()] for gj in Quat.basis()])

O0mat = matrix([list(g) for g in [Quat(1), i, (i+j)/2, (1+k)/2]])

################################################################

from cformat import Ibz, Object, ObjectFormatter

algobj = [Ibz(p), [[Ibz(v) for v in vs] for vs in gram]]
O0ord = [Ibz(O0mat.denominator()), [[Ibz(v*O0mat.denominator()) for v in vs] for vs in O0mat.transpose()]]
O0obj = [O0ord, [Ibz(1), [Ibz(c) for c in (0,1,0,0)]], [Ibz(1), [Ibz(c) for c in (0,0,1,0)]], 1]

objs = [[[Ibz(mat.denominator()), [[Ibz(v*mat.denominator()) for v in vs] for vs in mat.transpose()]], [Ibz(mat.denominator()), [Ibz(c*mat.denominator()) for c in ii]], [Ibz(1), [Ibz(c) for c in (0,0,1,0)]], q] for q,ii,mat in orders]

objs = ObjectFormatter([
        Object('quat_alg_t', 'QUATALG_PINFTY', algobj),
        Object('quat_order_t', 'MAXORD_O0', O0ord),
        Object('quat_p_extremal_maximal_order_t', 'STANDARD_EXTREMAL_ORDER', O0obj),
        Object('quat_p_extremal_maximal_order_t[]', 'ALTERNATE_EXTREMAL_ORDERS', objs),
    ])

with open('include/quaternion_data.h','w') as hfile:
    with open('quaternion_data.c','w') as cfile:
        print(f'#include <intbig.h>', file=hfile)
        print(f'#include <quaternion.h>', file=hfile)
        print(f'#include <stddef.h>', file=cfile)
        print(f'#include <stdint.h>', file=cfile)
        print(f'#include <quaternion_data.h>', file=cfile)

        print(f'#define NUM_ALTERNATE_EXTREMAL_ORDERS {len(orders)}', file=hfile)

        objs.header(file=hfile)
        objs.implementation(file=cfile)

