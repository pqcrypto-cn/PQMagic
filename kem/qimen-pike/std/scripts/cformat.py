#!/usr/bin/env python3
import sys, itertools
from math import floor, log
import sage.all

class Ibz:
    def __init__(self, v):
        self.v = int(v)
    def _literal(self, sz):
        val = int(self.v)
        sgn = val < 0
        num_limbs = (abs(val).bit_length() + sz-1) // sz if val else 0
        limbs = [(abs(val) >> sz*i) & (2**sz-1) for i in range(num_limbs or 1)]
        data = {
                '._mp_alloc': 0,
                '._mp_size': (-1)**sgn * num_limbs,
                '._mp_d': '(mp_limb_t[]) {' + ','.join(map(hex,limbs)) + '}',
            }
        return '{{' + ', '.join(f'{k} = {v}' for k,v in data.items()) + '}}'

class Object:
    def __init__(self, ty, name, obj):
        if '[' in ty:
            idx = ty.index('[')
            depth = ty.count('[]')
            def rec(os, d):
                assert d >= 0
                if not d:
                    return ()
                assert isinstance(os,list) or isinstance(os,tuple)
                r, = {rec(o, d-1) for o in os}
                return (len(os),) + r
            dims = rec(obj, depth)
            self.ty = ty[:idx], ''.join(f'[{d}]' for d in dims)
        else:
            self.ty = ty, ''
        self.name = name
        self.obj = obj

    def _declaration(self):
        return f'extern const {self.ty[0]} {self.name}{self.ty[1]};'

    def _literal(self, mp_limb_t_bits):
        def rec(obj):
            if isinstance(obj, int):
                return hex(obj)
            if isinstance(obj, sage.all.Integer):
                return hex(obj)
            if isinstance(obj, Ibz):
                return obj._literal(mp_limb_t_bits)
            if isinstance(obj, list) or isinstance(obj, tuple):
                return '{' + ', '.join(map(rec, obj)) + '}'
            raise NotImplementedError(f'unknown type {type(obj)} in Formatter')
        return rec(self.obj)

    def _definition(self, mp_limb_t_bits):
        return f'const {self.ty[0]} {self.name}{self.ty[1]} = ' + self._literal(mp_limb_t_bits) + ';'


class ObjectFormatter:
    def __init__(self, objs):
        self.objs = objs

    def header(self, file=None):
        for obj in self.objs:
            assert isinstance(obj, Object)
            print(obj._declaration(), file=file)

    def implementation(self, file=None):
        print('#if 0', file=file)
        for sz in (16, 32, 64):
            print(f'#elif 8*DIGIT_LEN == {sz}', file=file)
            for obj in self.objs:
                assert isinstance(obj, Object)
                print(obj._definition(sz), file=file)
        print('#endif', file=file)



def field(v, F=None):
    if F:
        v = F(v)
    p = F.characteristic()
    l = 1 + floor(log(p,2**64))
    vs = [[(c >> 64*i) & (2**64-1) for i in range(l)] for c in v]
    return vs

def xonly(T, *args):
    if not T: raise NotImplementedError('is point at infinity')
    x, _ = T.xy()
    return field(x, *args)

