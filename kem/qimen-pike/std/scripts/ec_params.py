#importing sys module
import sys
# importing os module
import os
# # importing click
# import click
# importing math
import math
# importing sage
from sage.all import *

import functools

# The following benchmarks are required for computing optimal strategies.
# The costs can be specified in arbitrary units and can be obtained by
# running the corresponding NGCC benchmark for the target parameter set,
# or left as "None" to use a
# generic estimate.
# ++++++++++ 
p2 =  0   # cost of xdbl
q4 = 0    # cost of xeval4

## NGCC_1 costs
# p2 = 1766
# q4 = 2452

## NGCC_2 costs
#p2 = 4071
#q4 = 5224

## NGCC_3 costs
#p2 = 7755
#q4 = 9847
# ++++++++++

def fp2str(x : int, p : int):
    nwords = (p.bit_length()-1)//64 + 1
    X = hex(x%p)[2:]
    while len(X) < 16*nwords:
        X='0'+X
    output = '{ '
    for i in range(nwords):
        output += '0x'+X[16*(nwords-1-i):16*(nwords-i)]+', '
    output = output[:-2]+' }'
    return output

def list2str(x):
    out = '{ '
    for a in x:
        out += str(a)+', '
    out = out[:-2] + ' }'
    return out

# Optimal strategy
def strategy(n, p, q):
    S = { 1: [] }
    C = { 1: 0 }
    for i in range(2, n+1):
        b, cost = min(((b, C[i-b] + C[b] + b*p + (i-b)*q) for b in range(1,i)),
                      key=lambda t: t[1])
        S[i] = [b] + S[i-b] + S[b]
        C[i] = cost
    return S[n]

# Function to read pike_parameters.txt and initial config
def config():

    # Read file parameters
    f = open('pike_parameters.txt')
    f.readline()
    p_input_line = f.readline()
    B_input_line = f.readline()
    f.readline()
    f.readline()
    use_twist_input_line = f.readline()
    f.close()
    try:
        p = int(p_input_line.split('0x')[-1],16)
        B = int(B_input_line.split(' = ')[-1])
        use_twist = int(use_twist_input_line.split(' = ')[-1])
        assert(B_input_line[:4+len(str(B))] == 'B = '+str(B) and p_input_line[:4+len(hex(p))] == 'p = '+hex(p))
    except:
        print("Error reading pike_parameters.txt. Ensure file contests have the following form:\nlvl = x\np = 0x[hexstring]\nB = [decimalstring]")
        exit(-1)

    # Factorization
    factorization = factor(p+1,limit=B)
    if not factorization[0][0]==2 and factorization[1][0]==3:
        print("Error: prime does not have the form p = f*2^a*3^b-1")
        exit(-1)
    POWER_OF_2 = factorization[0][1]
#    POWER_OF_3 = factorization[1][1]
#    if factorization[2][0]==5:
#        POWER_OF_5 = factorization[2][1]
    Pfactors = [factor[0] for factor in factorization[1:] if factor[0] <= B]
    PLS = prod(factorization[i][0]**factorization[i][1] for i in range(len((Pfactors))+1))
    Tpls = PLS // 2**POWER_OF_2

    # factorization = factor(p-1)
    # Mfactors = [factor[0] for factor in factorization[1:] if factor[0] <= B]
    Mfactors = []
    if use_twist == 1:
        Mfactors = [5]
        factorization2 = factor(p-1,limit=100)
        Mfactors = [factorization2[1][0]]
        POWER_OF_Tmin = factorization2[1][1]
        Tmin = factorization2[1][0]**factorization2[1][1]        # temp modification
        if n(log(p,2))>1000:
            Mfactors = [11]
            POWER_OF_Tmin = 247
            Tmin = 11**247
#        POWER_OF_5 = factorization2[1][1]
    return p,POWER_OF_2,PLS,Tpls,Tmin,Pfactors,Mfactors


sys.setrecursionlimit(1500)

# n = length of chain
# M = Cost of Multiplication
# S = Cost of Squaring
# I = Cost of Inversion
# data = [n, M, S, I]
def optimised_strategy(n, M, S, I):
    """
    A modification of

    Algorithm 60: https://sike.org/files/SIDH-spec.pdf Shown to be appropriate
    for (l,l)-chains in https://ia.cr/2023/508

    Which allows the leftmost branch to have a different cost for the rest of
    the tree. This is partiularly useful for (2,2) isogenies, where the gluing
    doubling and images have a much higher cost than the rest of the tree.

    Thanks to Robin Jadoul for helping with the implementation of this function 
    via personal communication
    """

    # Define the costs and initalise the nodes which we store during doubling
    left_cost = (8*M + 8*S, 12*M + 12*S)       # (regular_cost, left_branch_cost) Double
    right_cost = (4*M + 4*S, 84*M + 18*S)  # (regular_cost, first_right_cost) Images
    checkpoints = ({}, {})  # (inner, left edge)

    @functools.cache
    def cost(n, leftmost):
        """
        The minimal cost to get to all children of a height `n` tree.
        If `leftmost` is true, we're still on the leftmost edge of the "outermost" tree

        Updates a global "Check points" which are the points along a branch which we 
        keep for later
        """
        if n <= 1:
            return 0  # no cost here

        c = float("inf")
        for i in range(1, n):  # where to branch off
            # We need `i` moves on the left branch and `n - i` on the right branch
            # to make sure the corresponding subtrees don't overlap and everything
            # is covered exactly once
            thiscost = sum([
                cost(n - i, leftmost),    # We still need to finish off our walk to the left
                i * left_cost[leftmost],  # The cost for the moves on the left branch
                cost(i, False),           # The tree on the right side, now definitely not leftmost
                right_cost[leftmost] + (n - i - 1) * right_cost[False],  # The cost of moving right, maybe one at the first right cost
            ])
            # If a new lower cost has been found, update values
            if thiscost < c:
                c = thiscost
                checkpoints[leftmost][n] = i
        return c

    def convert(n, checkpoints):
        """
        Given a list of checkpoints, convert this to a list of
        the number of doublings to compute and keep before 
        pushing everything through an isogeny. This forces the
        output to match the more usual implementation, e.g.
        https://crypto.stackexchange.com/a/58377

        Warning! Everything about this function is very hacky, but does the job!
        """
        kernels = [n]
        doubles = []
        leftmost = 1

        # We always select the last point in our kernel
        while kernels != []:
            point = kernels[-1]
            if point == 1:
                # Remove this point and push everything through the isogeny
                kernels.pop()
                kernels = [k - 1 for k in kernels]
                leftmost = 0
            else:
                # checkpoints tells us to double this d times
                d = checkpoints[leftmost][point]
                # Remember that we did this
                doubles.append(d)
                kernels.append(point - d)
        return doubles

    # Compute the cost and populate the checkpoints
    c = cost(n, True)

    # Use the checkpoints to compute the list
    l = convert(n, checkpoints)

    return l



if __name__ == '__main__':
    p,POWER_OF_2,PLS,Tpls,Tmin,Pfactors,Mfactors = config()
    PMfactors = Pfactors + Mfactors

    if p2==0 and q4==0:
        p2 = 10
        q4 = 13

    sizeI = [ceil(sqrt((l-1)/4)) for l in PMfactors]
    sizeJ = [floor((l-1)/4/ceil(sqrt((l-1)/4))) for l in PMfactors]
    sizeK = [int((l-1)/2 - 2*ceil(sqrt((l-1)/4))*floor((l-1)/4/ceil(sqrt((l-1)/4)))) for l in PMfactors]

    number_strategy_4_isog = POWER_OF_2//2+10
    number_strategy_dim2_isog = POWER_OF_2//2+10

    # For Dlog_3
    # THREEe = 0
    # THREEpE = 1
    # while THREEpE * 3 < 2**64:
    #     THREEpE *= 3
    #     THREEe += 1

    # For Dlog_5
    # FIVEe = 0
    # FIVEpE = 1
    # while FIVEpE * 5 < 2**64:
    #     FIVEpE *= 5
    #     FIVEe += 1

    f = open('include/ec_params.h', 'w')
    print("computing ec_params.h")
    f.write('#ifndef EC_PARAMS_H\n')
    f.write('#define EC_PARAMS_H\n')
    f.write('\n')
    f.write('#include <fp_constants.h>\n')
    f.write('\n')
    f.write(f'#define POWER_OF_2 {POWER_OF_2}\n')
#    f.write(f'#define POWER_OF_3 {POWER_OF_3}\n')
#    f.write(f'#define POWER_OF_5 {POWER_OF_5}\n')
#    f.write(f'#define THREEe {THREEe}\n')
#    f.write(f'#define FIVEe {FIVEe}\n')
    f.write('\n')
    f.write(f'static digit_t TWOpF[NWORDS_ORDER] = {fp2str(2**POWER_OF_2, p)}; // Fp representation for the power of 2\n')
    f.write(f'static digit_t TWOpFm1[NWORDS_ORDER] = {fp2str(2**(POWER_OF_2-1), p)}; // Fp representation for half the power of 2\n')
#    f.write(f'static digit_t THREEpE[NWORDS_ORDER] = {fp2str(THREEpE, p)}; // THREEpE = 3^THREEe < 2^64\n')
#    f.write(f'static digit_t THREEpF[NWORDS_ORDER] = {fp2str(3**(POWER_OF_3), p)}; // Fp representation for the power of 3\n')
#    f.write(f'static digit_t FIVEpE[NWORDS_ORDER] = {fp2str(FIVEpE, p)}; // FIVEpE = 5^FIVEe < 2^64\n')
#    f.write(f'static digit_t FIVEpF[NWORDS_ORDER] = {fp2str(5**(POWER_OF_5), p)}; // Fp representation for the power of 5\n')
#    f.write(f'static digit_t THREEpFdiv2[NWORDS_ORDER] = {fp2str(3**(POWER_OF_3)//2, p)}; // Floor of half the power of 3\n')
#    f.write(f'static digit_t FIVEpFdiv2[NWORDS_ORDER] = {fp2str(5**(POWER_OF_5)//2, p)}; // Floor of half the power of 5\n')
    f.write('\n')
    f.write('#define scaled 1 // unscaled (0) or scaled (1) remainder tree approach for squareroot velu\n')
    f.write('#define gap 83 // Degree above which we use squareroot velu reather than traditional\n')
    f.write('\n')
    f.write(f'#define P_LEN {len(Pfactors)} // Number of odd primes in p+1\n')
    f.write(f'#define M_LEN {len(Mfactors)} // Number of odd primes in p-1\n')
    f.write('\n')
    f.write('// Bitlength of the odd prime factors\n')
    f.write(f'static digit_t p_plus_minus_bitlength[P_LEN + M_LEN] = \n\t{list2str([int(l).bit_length() for l in Pfactors] + [int(l).bit_length() for l in Mfactors])};\n')
    f.write('\n')
    f.write('// p+1 divided by the power of 2\n')
    f.write(f'static digit_t p_cofactor_for_2f[{(((p+1)//2**POWER_OF_2).bit_length()-1)//64+1}] = {fp2str((p+1)//2**POWER_OF_2, (p+1)//2**POWER_OF_2+1)};\n')
    f.write(f'#define P_COFACTOR_FOR_2F_BITLENGTH {((p+1)//2**POWER_OF_2).bit_length()}\n')
    f.write('\n')
    f.write('// p+1 divided by PLUS\n')
    f.write(f'static digit_t p_cofactor_for_PLUS[{(((p+1)//PLS).bit_length()-1)//64+1}] = {fp2str((p+1)//PLS, (p+1)//PLS+1)};\n')
    f.write(f'#define P_COFACTOR_FOR_PLUS_BITLENGTH {((p+1)//PLS).bit_length()}\n')
    f.write('\n')
    f.write('// p+1 divided by Tpls\n')
    f.write(f'static digit_t p_cofactor_for_Tpls[{(((p+1)//Tpls).bit_length()-1)//64+1}] = {fp2str((p+1)//Tpls, (p+1)//Tpls+1)};\n')
    f.write(f'#define P_COFACTOR_FOR_TPLS_BITLENGTH {((p+1)//Tpls).bit_length()}\n')
    f.write('\n')
    f.write('// p-1 divided by Tmin\n')
    f.write(f'static digit_t p_cofactor_for_Tmin[{(((p-1)//Tmin).bit_length()-1)//64+1}] = {fp2str((p-1)//Tmin, (p-1)//Tmin+1)};\n')
    f.write(f'#define P_COFACTOR_FOR_TMIN_BITLENGTH {((p-1)//Tmin).bit_length()}\n')
    f.write('\n')
    f.write('// Strategy for 4-isogenies\n')
    f.write(f'static int STRATEGY4[{number_strategy_dim2_isog}][{POWER_OF_2//2}]='+'{\n')
    for i in range(0,number_strategy_4_isog):
        f.write(f'{list2str(strategy((POWER_OF_2-i)//2, 2*p2, q4)+[0]*((i+1)//2))},\n')
    f.write(f''+'};')
    f.write('\n')
    f.write('// Optimal sizes for I,J,K in squareroot Velu\n')
    f.write(f'static int sizeI[{len(sizeI)}] =\n\t{list2str(sizeI)};\n')
    f.write(f'static int sizeJ[{len(sizeJ)}] =\n\t{list2str(sizeJ)};\n')
    f.write(f'static int sizeK[{len(sizeK)}] =\n\t{list2str(sizeK)};\n')
    f.write('\n')
    f.write(f'#define sI_max {max(sizeI)}\n')
    f.write(f'#define sJ_max {max(sizeJ)}\n')
    f.write(f'#define sK_max {max(max(sizeK), 83)}\n')
    f.write('\n')
    # f.write(f'#define ceil_log_sI_max {ceil(log(max(sizeI),2))}\n')
    # f.write(f'#define ceil_log_sJ_max {ceil(log(max(sizeJ),2))}\n')
    f.write('\n')
    f.write('// Strategies for dim2 isogenies\n')
    f.write(f'static int strategies[{number_strategy_dim2_isog}][{POWER_OF_2-1}]='+'{\n')
    for i in range(0,number_strategy_dim2_isog):
        f.write(f'{list2str(optimised_strategy(POWER_OF_2-i,75,52,3314)+[0]*(i))},\n')
    f.write(f''+'};')
    f.write('\n')
    f.write('#endif\n')

    f.close()
