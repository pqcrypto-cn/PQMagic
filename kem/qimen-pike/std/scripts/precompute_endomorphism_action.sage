#!/usr/bin/env sage
proof.all(False)  # faster
from cubical_pairings import cubical_tate_pairing
from sage.misc.banner import require_version
if not require_version(10, 0, print_message=True):
    exit('')

################################################################

from parameters import p, B, Cfactor, use_cfactor, use_twist, f, Tpls, Tmin, Dchall, expC, TORSION_D
from modarith_params import get_modarith_params
_ma = get_modarith_params(p)
_ma_nlimbs = _ma['nlimbs']
_ma_radix = _ma['radix']
_ma_R = 2**(_ma_nlimbs * _ma_radix)  # Montgomery R for modarith
if use_twist == 0:
    T = Tpls # * Tmin
else:
    T = Tpls * Tmin
################################################################

if p % 4 != 3:
    raise NotImplementedError('requires p ≡ 3 (mod 4)')

if use_twist == 1:
    pfact = list((p^2-1).factor(limit = 8))
    plist = [l for (l,e) in pfact]
else:
    pfact = (p+1).factor(limit = 8)
    plist = [l for (l,e) in pfact]

Fp2.<i> = GF((p,2), modulus=[1,0,1])
Fp4 = Fp2.extension(2, 'u')
if use_twist == 0:
    E = EllipticCurve(Fp2, [1,0])
    E.set_order((p+1)^2)
    assert E.j_invariant() == 1728
    assert E.is_supersingular()
    assert E.change_ring(Fp2).frobenius() == -p
    #if use_twist == 1 : assert E.order() == (p^2-1)^2
    endo_1 = E.scalar_multiplication(1)
    endo_i = E.automorphisms()[-1]
    endo_j = E.frobenius_isogeny()
    endo_k = endo_i * endo_j
if use_twist == 1:
    E_ext = EllipticCurve(Fp4, [1,0])
    E_ext.set_order((p^2-1)^2)
    assert E_ext.j_invariant() == 1728
    assert E_ext.is_supersingular()
    assert E_ext.change_ring(Fp2).frobenius() == -p
    endo_1 = E_ext.scalar_multiplication(1)
    endo_i = E_ext.automorphisms()[-1]
    endo_j = E_ext.frobenius_isogeny()
    endo_k = endo_i * endo_j

if 0:  # skipped for speed, for now
    assert endo_i^2 == E.scalar_multiplication(-1)
    assert endo_j^2 == E.scalar_multiplication(-p)
    assert endo_j * endo_i == - endo_i * endo_j
else:
    if use_twist == 0:
        R = E.random_point()
    else:
        R = E_ext.random_point()
    assert (endo_i^2)(R) == -1*R
    assert (endo_j^2)(R) == -p*R
    assert (endo_j*endo_i)(R) == -(endo_i*endo_j)(R)
    if use_twist == 1:
        scalar = (p-1) // Cfactor**expC
        R *= scalar
        # temp modification
        if n(log(p,2))>1000:
            o = order_from_multiple(TORSION_D*R, (p^2-1)//scalar//TORSION_D)
            o = o * TORSION_D
        else:
            o = order_from_multiple(R, (p^2-1)/scalar)
        R.set_order(o)


if use_twist == 1:
    def half_endo(summands):
        def _eval(P):
            E = P.curve()
            assert P in E
            F = E.base_field()
            if (halves := P.division_points(2)):
                Q = halves[0]
            else:
                Q = E.change_ring(F.extension(2,'v'))(P)
            R = sum(endo._eval(Q) for endo in summands)
            return E(R)
        return _eval
else:
    def half_endo(summands):
        def _eval(P):
            E = P.curve()
            assert P in E
            F = E.base_field()
            R = sum(endo._eval(P) for endo in summands)
            Q = R.division_points(2)[0]
            return Q
        return _eval

################################################################

from sage.groups.generic import order_from_multiple

if use_twist == 0:
    x = Fp2.gen()
    while True:
        x += 1
        try:
            P = E.lift_x(x)
        except ValueError:
            continue
        o = order_from_multiple(P, (p+1), plist)
        if o == p+1 and ((p+1)//2)*P == E([0,0]):
            break
    assert P.order() == p+1
    x = -Fp2.gen()
    while True:
        x += 1
        try:
            Q = E.lift_x(x)
        except ValueError:
            continue
        o = order_from_multiple(Q, (p+1), plist)
        if o != p+1:
            continue
        assert (T<<f) == p+1
        assert Q.order() == p+1
        e = order_from_multiple(P.weil_pairing(Q, p+1), p+1, operation='*')
        if e == p+1:
            break
    assert P.order() == p+1
    assert Q.order() == p+1
    assert order_from_multiple(P.weil_pairing(Q, p+1), p+1, operation='*') == p+1
if use_twist == 1:
    scalar = (p^2-1) // T // 2**f
    x = Fp4.gen()
    while True:
        x += 1
        try:
            P = E_ext.lift_x(x)
        except ValueError:
            continue
        # Indeed, we need to check Ps has full order. 
        # Be careful when using Ps and Ppt. 
        Ps = ((p-1) * (p+1) // TORSION_D) * P
        P *= scalar
        Ppt = mod((2**f * Tpls)^-1, TORSION_D) * Ps + mod((2**f * TORSION_D)^-1, Tpls) * (2**f * Tmin * P) + mod((Tpls * TORSION_D)^-1, 2**f) * (Tpls * Tmin * P)
        o = order_from_multiple(P, (p^2-1)/scalar)
        if (T<<f).divides(o):
            if ((T<<f)/2)*P == E_ext([0,0]):
                P *= o // (T<<f)
                if n(log(p,2))<1000:
                    assert order_from_multiple(P, (p^2-1)/scalar) == T<<f
                P.set_order(T*2**f)
                break
    
    x = -Fp4.gen()
    while True:
        x += 1
        try:
            Q = E_ext.lift_x(x)
        except ValueError:
            continue
        Qs = ((p-1) * (p+1) // TORSION_D) * Q
        Q *= scalar
        Qpt = mod((1<<f)^-1, TORSION_D) * Qs + mod(TORSION_D^-1, 1<<f) * (T * Q)
        o = order_from_multiple(Q, (p^2-1)/scalar) 
        if not (T<<f).divides(o):
            continue
        Q *= o // (T<<f)
        if n(log(p,2))<1000:
            assert order_from_multiple(Q, (p^2-1)/scalar) == T<<f
        Q.set_order(T*2**f)
        label = 0
        if order_from_multiple(P.weil_pairing(Q, T<<f), T<<f, operation='*') == T<<f:
            # pv = cubical_weil_pairing(Ps, Qs, TORSION_D, 0)
            pv = cubical_tate_pairing(Ps, Qs, TORSION_D, 2, p, 0)
            if n(log(p,2))<1000:
                fac = factor(TORSION_D)
                for ii in range(2,len(fac)):
                    texp = (p+1)//fac[ii][0]
                    if pv**texp == 1:
                        label = 1      
            if label == 0: 
                break

gen1 = endo_1._eval
gen2 = endo_i._eval
gen3 = half_endo([endo_i, endo_j])
gen4 = half_endo([endo_1, endo_k])

def dlp(P, Q, R):
    n = P.order()
    assert(n != 0)
    assert P.order() == Q.order()
    if use_twist == 0:
        assert (order_from_multiple(R, p+1, plist)).divides(P.order())
    #else:
    #    assert R.order().divides(P.order())
    e = Fp2(P.weil_pairing(Q, n))
    a = Fp2(R.weil_pairing(Q, n))
    a = discrete_log(a,e,n)
    b = Fp2(P.weil_pairing(R, n))
    b = discrete_log(b,e,n)
    assert a*P + b*Q == R
    return a, b

def matrix_of_isogeny(phi):
    imP, imQ = map(phi, (P,Q))
    vecP = dlp(P, Q, imP)
    vecQ = dlp(P, Q, imQ)
    mat = matrix(Zmod(T<<f), [vecP, vecQ]).transpose()
    assert imP == ZZ(mat[0][0])*P + ZZ(mat[1][0])*Q
    assert imQ == ZZ(mat[0][1])*P + ZZ(mat[1][1])*Q
    return mat


#mat1 = matrix_of_isogeny(endo_1)
mati = matrix_of_isogeny(endo_i)
matj = matrix_of_isogeny(endo_j)
matk = matrix_of_isogeny(endo_k)
#assert mat1 == 1    # identity; omit

#mat1 = matrix_of_isogeny(gen1)
mat2 = matrix_of_isogeny(gen2)
mat3 = matrix_of_isogeny(gen3)
mat4 = matrix_of_isogeny(gen4)
#assert mat1 == 1    # identity; omit

len_p = _ma_nlimbs
pv = pv * _ma_R

################################################################

from cformat import Ibz, Object, ObjectFormatter

def field2limbs(el):
    l = _ma_nlimbs
    el = Fp2(el)
    mask = (1 << _ma_radix) - 1
    vs = [[(int(c) >> _ma_radix*i) & mask for i in range(l)] for c in el]
    return vs

def fmt_basis(name, P, Q):
    vs = [
            [field2limbs(T[0] * _ma_R), field2limbs(T[2] * _ma_R)]
            for T in (P,Q,P-Q)
        ]
    return Object('ec_basis_t', name, vs)

if use_twist == 1:
    bases = {
            'EVEN': 1<<f,
            'ODD_PLUS': Tpls,
            'ODD_MINUS': Tmin,
            
        }
    assert P.order() == Q.order()
    
    objs = ObjectFormatter([
            fmt_basis(f'BASIS_{k}', ZZ(T*2**f/v)*P, ZZ(T*2**f/v)*Q)
            for k,v in bases.items()
        ] + [
            fmt_basis(f'BASIS_EVEN_AND_ODD_PLUS', ZZ(mod((Tpls)^-1, 1<<f))*ZZ(T)*P+ZZ(mod((2**f)^-1, Tpls))*ZZ(T*2**f/(Tpls))*P, ZZ(mod((Tpls)^-1, 1<<f))*ZZ(T)*Q+ZZ(mod((2**f)^-1, Tpls))*ZZ(T*2**f/(Tpls))*Q)
        ] + [
            Object('fp2_t', 'xPpt', field2limbs(Ppt[0] * _ma_R)),
            Object('fp2_t', 'xQpt', field2limbs(Qpt[0] * _ma_R)),
            Object('ec_curve_t', 'CURVE_E0', [[[int(0)]], [[int(1)]]]),
            Object('fp2_t', 'Pairing_value', field2limbs(pv)),
            Object('ibz_mat_2x2_t', 'ACTION_I', [[Ibz(v) for v in vs] for vs in mati]),
            Object('ibz_mat_2x2_t', 'ACTION_J', [[Ibz(v) for v in vs] for vs in matj]),
            Object('ibz_mat_2x2_t', 'ACTION_K', [[Ibz(v) for v in vs] for vs in matk]),
            Object('ibz_mat_2x2_t', 'ACTION_GEN2', [[Ibz(v) for v in vs] for vs in mat2]),
            Object('ibz_mat_2x2_t', 'ACTION_GEN3', [[Ibz(v) for v in vs] for vs in mat3]),
            Object('ibz_mat_2x2_t', 'ACTION_GEN4', [[Ibz(v) for v in vs] for vs in mat4]),
        ])
elif use_cfactor == 1 :
    bases = {
            'EVEN': 1<<f,
            'C': Cfactor**expC,
            'ODD_PLUS': Tpls,
            'ODD_MINUS': Tmin,
        }
    assert P.order() == Q.order()

    objs = ObjectFormatter([
            fmt_basis(f'BASIS_{k}', ZZ(P.order()/v)*P, ZZ(Q.order()/v)*Q)
            for k,v in bases.items()
        ] + [
            Object('ec_curve_t', 'CURVE_E0', [[[int(0)]], [[int(1)]]]),
            Object('ibz_mat_2x2_t', 'ACTION_I', [[Ibz(v) for v in vs] for vs in mati]),
            Object('ibz_mat_2x2_t', 'ACTION_J', [[Ibz(v) for v in vs] for vs in matj]),
            Object('ibz_mat_2x2_t', 'ACTION_K', [[Ibz(v) for v in vs] for vs in matk]),
            Object('ibz_mat_2x2_t', 'ACTION_GEN2', [[Ibz(v) for v in vs] for vs in mat2]),
            Object('ibz_mat_2x2_t', 'ACTION_GEN3', [[Ibz(v) for v in vs] for vs in mat3]),
            Object('ibz_mat_2x2_t', 'ACTION_GEN4', [[Ibz(v) for v in vs] for vs in mat4]),
        ])
else :
    bases = {
            'EVEN': 1<<f,
            'ODD_PLUS': Tpls,
            'ODD_MINUS': Tmin,
        }
    assert P.order() == Q.order()

    objs = ObjectFormatter([
            fmt_basis(f'BASIS_{k}', ZZ(P.order()/v)*P, ZZ(Q.order()/v)*Q)
            for k,v in bases.items()
        ] + [
            Object('ec_curve_t', 'CURVE_E0', [[[int(0)]], [[int(1)]]]),
            Object('ibz_mat_2x2_t', 'ACTION_I', [[Ibz(v) for v in vs] for vs in mati]),
            Object('ibz_mat_2x2_t', 'ACTION_J', [[Ibz(v) for v in vs] for vs in matj]),
            Object('ibz_mat_2x2_t', 'ACTION_K', [[Ibz(v) for v in vs] for vs in matk]),
            Object('ibz_mat_2x2_t', 'ACTION_GEN2', [[Ibz(v) for v in vs] for vs in mat2]),
            Object('ibz_mat_2x2_t', 'ACTION_GEN3', [[Ibz(v) for v in vs] for vs in mat3]),
            Object('ibz_mat_2x2_t', 'ACTION_GEN4', [[Ibz(v) for v in vs] for vs in mat4]),
        ])


with open('include/endomorphism_action.h','w') as hfile:
    with open('endomorphism_action.c','w') as cfile:
        print(f'#include <intbig.h>', file=hfile)
        print(f'#include <ec.h>', file=hfile)
        print(f'#include <quaternion.h>', file=hfile)
        print(f'#include <stddef.h>', file=cfile)
        print(f'#include <stdint.h>', file=cfile)
        print(f'#include <endomorphism_action.h>', file=cfile)

        objs.header(file=hfile)
        objs.implementation(file=cfile)

