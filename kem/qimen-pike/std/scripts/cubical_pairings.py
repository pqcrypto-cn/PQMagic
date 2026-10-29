from cubical_arithmetic import cubical_ladder, cubical_ladder_one_point


def _translate(P, T):
    """
    Algorithm 4: translate a point P by a point T in E[2]

    Args:
        P: (XP, ZP) x-only coordinates of the point to be translated
        T: (r, s) x-only coordinates of a point in E[2]

    Returns:
        Q: P + T = (XQ, ZQ), the affine translation of P by T
    """
    XP, ZP = P
    r, s = T

    # Compute the translation of P by T
    XQ = r * XP - s * ZP
    ZQ = s * XP - r * ZP

    if s.is_zero():
        # Handle edge case for when T = (1 : 0)
        XQ, ZQ = XP, ZP
    elif r.is_zero():
        # Handle edge case for when T = (0 : 1)
        XQ, ZQ = ZP, XP

    return XQ, ZQ


def _reduce_tate_pairing(ePQ, ell, k, q):
    """
    Helper function which computes ePQ^(q^k - 1)
    """
    # When q is not explicitly supplied, we can attempt to compute it ourselves
    if q is None:
        K = ePQ.base_ring()
        d = K.degree()
        if d.is_one():
            q = K.order()
        elif d == k:
            q = K.base_ring().order()
        else:
            raise ValueError("Correct value of field degree cannot be determined")

    # Ensure that the supplied value is what we expect it to be
    elif not ell.divides(q**k - 1):
        raise ValueError("ell does not divide q**k - 1 for the supplied value of q")

    # Reduce the Tate pairing
    exp = (q**k - 1) // ell
    return ePQ**exp


def _cubical_tate_pairing_T(P, Q, ell, k=None, q=None):
    """
    Helper function which can compute e(P, T) or e(T, P)
    for T = (0 : 1) where P and Q are not zero.

    This function allows the computation of the pairing without using
    a cubical ladder, avoiding the issue of inverting the x-coordinate of T
    """
    assert P.x().is_zero() or Q.x().is_zero(), "One of P or Q must be (0 : 1)"

    # For odd ell or when P = Q = T, the result of the is always 1
    if ell & 1 or P == Q:
        return P.base_ring().one()

    # For even ell = 2*m, we can compute e(T, Q) or e(T, P)
    # as a function with divisor ell(T)-ell(0) evaluated at Q.
    # We choose x^m as such function
    m = ell // 2

    # When P = T we compute the pairing directly
    if P.x().is_zero():
        ePT = Q.x() ** m

    # When Q = T we compute the pairing in the following way:
    # e(P, T) = e(T, P) * e_{W, 2}([m]P, T) = ±x(P)^m
    # e(T, P) = x(P)^m, as above
    # e_{W, 2}([m]P, T) = ±1 e(T, T) = e(0, T) = 1 and -1 otherwise
    else:
        # Compute e(T, P)
        mP = m * P
        ePT = P.x() ** m

        # Set the sign based on the Weil pairing
        if not (mP.is_zero() or mP.x().is_zero()):
            ePT = -ePT

    # Optionally reduce the pairing
    if k is not None:
        ePT = _reduce_tate_pairing(ePT, ell, k, q)

    return ePT


def cubical_tate_pairing(P, Q, ell, k=None, q=None, check=True):
    """
    Algorithm 5: compute the Tate pairing e_{T, ell}(P, Q) when
    ell is even, or it's square e_{T, ell}(P, Q)^2 when ell is
    odd.

    Args:
        P, Q: points on a Montgomery curve with P in E[ell]
        ell: integer for the Tate pairing

    Optional:
        k: the embedding degree such that ell divides p^k - 1
        q: the size of the base field (the larger field is GF(p^k))
           only needs to be set in a small number of cases
        check: whether to perform an additional scalar multiplication to
           ensure that P in E[ell]

    Returns:
        The Tate pairing e_{T, ell}(P, Q) for even ell and its
        square e_{T, ell}(P, Q)^2 when ell is odd

    Raises:
        ValueError: if P is not in E[ell] and check is true
    """
    # Ensure P is in the ell-torsion
    if check and not (ell * P).is_zero():
        raise ValueError("the point P must be in E[ell]")

    # Ensure P and Q are on the same curve
    if Q.curve() != P.curve():
        raise ValueError("the points P, Q must be on the same curve")
    PmQ = P - Q

    # Check for edge cases
    # If either P or Q are zero the Tate pairing is trivial
    if P.is_zero() or Q.is_zero():
        return P.base_ring().one()

    # For the generic case, the cubical ladder needs the inverses of x-coordinates
    # of P, Q and P - Q. If P, Q or P - Q = (0 : 1) = T we hit an edge case and
    # handle this separately
    elif P.x().is_zero() or Q.x().is_zero():
        # Handle edge case for when one out of P and Q is the point T = (0 : 1)
        # they won't be both equal to T, since we already checked P != Q
        return _cubical_tate_pairing_T(P, Q, ell, k, q)

    # When P - Q = T, we compute
    # e_{T, ell}(P, Q) = e_{T, ell}(P, P) / e_{T, ell}(P, T)
    elif not PmQ.is_zero() and PmQ.x().is_zero():
        ePP = cubical_tate_pairing(P, P, ell, k, q, check=False)
        ePT = _cubical_tate_pairing_T(P, P - Q, ell, k, q)
        return ePP / ePT

    # When ell is even, we divide by 2
    ell_is_even = not (ell & 1)
    if ell_is_even:
        n = ell // 2
    else:
        n = ell

    # Compute the pairing from the cubical ladder
    if PmQ.is_zero():
        nP, nPQ = cubical_ladder_one_point(P, n)
    else:
        nP, nPQ = cubical_ladder(P, Q, n)

    # Translate by [n]P, the point of order two, if ell was even
    if ell_is_even:
        nPQ = _translate(nPQ, nP)
        nP = _translate(nP, nP)

    # The pairing is the Z coordinate of [n]P + Q divided by the
    # X coordinate of [n]P
    pairing = nPQ[1] / nP[0]

    # To compute the reduced tate pairing, we compute
    # e_{T,ell}(P, Q)^(q^k - 1), which is only done when the embedding
    # degree is given explicitly to the function
    if k is not None:
        pairing = _reduce_tate_pairing(pairing, ell, k, q)

    return pairing


def cubical_weil_pairing(P, Q, ell, check=True):
    """
    Algorithm 6: compute the Weil pairing e_{W, ell}(P, Q) when
    ell is even, or it's square e_{W, ell}(P, Q)^2 when ell is
    odd.

    Args:
        P, Q: points on a Montgomery curve with P, Q in E[ell]
        ell: integer for the Weil pairing

    Optional:
        check: (bool) perform an additional scalar multiplication to
               ensure that P in E[ell]

    Returns:
        The Weil pairing e_{W, ell}(P, Q) for even ell and its
        square e_{W, ell}(P, Q)^2 when ell is odd

    Raises:
        ValueError: if P or Q is not in E[ell] and check is true
    """
    # Optionally ensure P, Q are in E[ell]
    if check and not ((ell * P).is_zero() and (ell * Q).is_zero()):
        raise ValueError("the points P, Q must be in E[ell]")

    if Q.curve() != P.curve():
        raise ValueError("the points P, Q must be on the same curve")

    # If P or Q = E(0) or P = ±Q then the Weil pairing is trivial
    if any(X.is_zero() for X in [P, Q, P + Q, P - Q]):
        return P.base_ring().one()

    # The Weil pairing is the ratio of two non-reduced Tate pairings
    t1 = cubical_tate_pairing(P, Q, ell, check=False)
    t2 = cubical_tate_pairing(Q, P, ell, check=False)
    return t1 / t2
