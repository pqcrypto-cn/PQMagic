def compute_A24(E):
    """
    Return the constant (A + 2)/4 from a Montgomery curve
    E : y^2 = x^3 + Ax^2 + x

    Args:
        E: an elliptic curve in Montgomery form

    Returns:
        A24: the constant (A + 2) / 4

    Raises:
        ValueError: if the curve is not in Montgomery form
    """
    A = E.a2()
    if E.a_invariants() != (0, A, 0, 1, 0):
        raise ValueError("curve is not in Montgomery form")
    A24 = (A + 2) / 4
    return A24


def XZ(P):
    """
    Convert a point P on a Montgomery curve to its x-only coordinates
    (XP, ZP) using the Kummer line representation

    Args:
        P: point on a Montgomery curve

    Returns:
        XP, ZP: x-only coordinates of the point P
    """
    if not P.is_zero():
        XP = P.x()
        ZP = P.base_ring().one()
    else:
        XP = P.base_ring().one()
        ZP = P.base_ring().zero()
    return (XP, ZP)


def cubical_dbl(P, A24):
    """
    Algorithm 1: double a point using cubical arithmetic

    Args:
        P: (XP, ZP) x-only coordinates of the point to be doubled
        A24: (A + 2) / 4 where A is the Montgomery coefficient of the curve

    Returns:
        X2, Z2: coordinates of the doubled point [2](XP : ZP)
    """
    XP, ZP = P

    t0 = (XP + ZP) ** 2
    t1 = (XP - ZP) ** 2
    X2 = t0 * t1
    t2 = t0 - t1
    t0 = A24 * t2
    Z2 = t2 * (t0 + t1)
    return X2, Z2


def cubical_diff_add(P, Q, ixPQ):
    """
    Algorithm 2: add two points using cubical arithmetic

    Args:
        P: (XP, ZP) x-only coordinates of the point P
        Q: (XQ, ZQ) x-only coordinates of the point Q
        ixPQ: inverse of the normalised x-coordinate of x(P - Q)

    Returns:
        R: (XR, ZR) x-only coordinates of the point P + Q
    """
    XP, ZP = P
    XQ, ZQ = Q

    t0 = (XP - ZP) * (XQ + ZQ)
    t1 = (XP + ZP) * (XQ - ZQ)
    XR = ixPQ * (t0 + t1) ** 2
    ZR = (t0 - t1) ** 2
    XR = XR / 4
    ZR = ZR / 4
    return XR, ZR


def cubical_ladder_one_point(P, n):
    """
    Algorithm 3: compute [n]P and [n+1]P for some integer n
    and point P using cubical arithmetic

    Args:
        P: point on a Montgomery curve
        n: the scalar to multiply by

    Returns:
        XnP, ZnP: x-only coordinates of the point [n]P
        XnPP, ZnPP: x-only coordinates of the point [n+1]P

    Raises:
        ValueError: if E is not an elliptic curve in Montgomery form
        ValueError: if n is negative
    """
    # Ensure the scalar is in the expected form
    if n < 0:
        raise ValueError("scalar must be non-negative")

    # Ensure P and Q are on the same curve
    E = P.curve()

    # Ensure E is in Montgomery form and compute (A + 2) / 4
    A24 = compute_A24(E)

    # Represent the points P on the Kummer line as (X : Z)
    P_tilde = XZ(P)

    # Initalise points for the cubical ladder
    S0 = XZ(P.curve().zero())
    S1 = P_tilde

    # When n == 0 we return 0, Q
    if n == 0:
        return S0, S1
    if n == 1:
        return S1, cubical_dbl(S1, A24)

    # We compute the inverse x-coordinate of P
    # using that Sage always normalises points such that Z = 1
    ixP = 1 / P.x()

    # Iterate from the MSB to the LSB
    for bit in bin(n)[2:]:
        R = cubical_diff_add(S0, S1, ixP)
        if bit == "0":
            S0 = cubical_dbl(S0, A24)
            S1 = R
        else:
            S1 = cubical_dbl(S1, A24)
            S0 = R
    return S0, S1


def cubical_ladder(P, Q, n):
    """
    Algorithm 3: compute [n]P and [n]P + Q for some integer
    n and points P, Q using cubical arithmetic

    Args:
        P, Q: points on a Montgomery curve
        n: the scalar to multiply by

    Returns:
        XnP, ZnP: x-only coordinates of the point [n]P
        XnPQ, ZnPQ: x-only coordinates of the point [n]P + Q

    Raises:
        ValueError: if P, Q are not on the same curve
        ValueError: if E is not an elliptic curve in Montgomery form
        ValueError: if n is negative
    """
    # Ensure the scalar is in the expected form
    if n < 0:
        raise ValueError("scalar must be non-negative")

    # Ensure P and Q are on the same curve
    E = P.curve()
    if E != Q.curve():
        raise ValueError("points P, Q are not the same curve")

    # Ensure E is in Montgomery form and compute (A + 2) / 4
    A24 = compute_A24(E)

    # Represent the points P and Q on the Kummer line as (X : Z)
    # we use that Sage always normalises points such that Z = 1
    P_tilde = XZ(P)
    Q_tilde = XZ(Q)

    PQ = P - Q
    if (P - Q).is_zero():
        return cubical_ladder_one_point(P, n)

    # Initalise points for the cubical ladder
    S0 = XZ(P.curve().zero())
    S1 = P_tilde
    T = Q_tilde

    # When n == 0 we return 0, Q
    if n == 0:
        return S0, T

    # We compute the inverse x-coordinates of the three points
    # using that Sage always normalises points such that Z = 1
    ixP = 1 / P.x()
    ixQ = 1 / Q.x()
    ixPQ = 1 / PQ.x()

    # Iterate from the MSB to the LSB
    for bit in bin(n)[2:]:
        R = cubical_diff_add(S0, S1, ixP)
        if bit == "0":
            T = cubical_diff_add(T, S0, ixQ)
            S0 = cubical_dbl(S0, A24)
            S1 = R
        else:
            T = cubical_diff_add(T, S1, ixPQ)
            S1 = cubical_dbl(S1, A24)
            S0 = R
    return S0, T
