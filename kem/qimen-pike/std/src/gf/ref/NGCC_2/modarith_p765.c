
//Automatically generated modular arithmetic C code
//Command line : python monty.py 64 0x1bfa60de9c0419b7bf54fba3dbb47692301e3eeaebbf1ce8a1434ee88e42e1e6140243d6c8bdb2744acf5820369b15b0e7bb8e9933551de530eb7aa16fc48c0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
//Python Script by Mike Scott (Technology Innovation Institute, UAE, 2025)

#include <stdio.h>
#include <stdint.h>

#define sspint int64_t
#define spint uint64_t
#define dpint __uint128_t
#define sdpint __int128_t
#define Wordlength 64
#define Nlimbs 13
#define Radix 59
#define Nbits 765
#define Nbytes 96

#define MONTGOMERY
//propagate carries
static spint inline prop(spint *n) {
	int i;
	spint mask=((spint)1<<59u)-(spint)1;
	sspint carry=(sspint)n[0];
	carry>>=59u;
	n[0]&=mask;
	for (i=1;i<12;i++) {
		carry+=(sspint)n[i];
		n[i] = (spint)carry & mask;
		carry>>=59u;
	}
	n[12]+=(spint)carry;
	return -((n[12]>>1)>>62u);
}

//propagate carries and add p if negative, propagate carries again
static spint flatten(spint *n) {
	spint carry=prop(n);
	n[0]-=(spint)1u&carry;
	n[4]+=((spint)0x216fc48c1000000u)&carry;
	n[5]+=((spint)0x266aa3bca61d6f5u)&carry;
	n[6]+=((spint)0x5a6c56c39eee3a6u)&carry;
	n[7]+=((spint)0x5ed93a2567ac101u)&carry;
	n[8]+=((spint)0x2e1e6140243d6c8u)&carry;
	n[9]+=((spint)0x39d142869dd11c8u)&carry;
	n[10]+=((spint)0x248c078fbabaefcu)&carry;
	n[11]+=((spint)0x3dfaa7dd1edda3bu)&carry;
	n[12]+=((spint)0x1bfa60de9c0419bu)&carry;
	(void)prop(n);
	return (carry&1);
}

//Montgomery final subtract
static spint modfsb(spint *n) {
	n[0]+=(spint)1u;
	n[4]-=(spint)0x216fc48c1000000u;
	n[5]-=(spint)0x266aa3bca61d6f5u;
	n[6]-=(spint)0x5a6c56c39eee3a6u;
	n[7]-=(spint)0x5ed93a2567ac101u;
	n[8]-=(spint)0x2e1e6140243d6c8u;
	n[9]-=(spint)0x39d142869dd11c8u;
	n[10]-=(spint)0x248c078fbabaefcu;
	n[11]-=(spint)0x3dfaa7dd1edda3bu;
	n[12]-=(spint)0x1bfa60de9c0419bu;
	return flatten(n);
}

//Modular addition - reduce less than 2p
static void modadd(const spint *a,const spint *b,spint *n) {
	spint carry;
	n[0]=a[0]+b[0];
	n[1]=a[1]+b[1];
	n[2]=a[2]+b[2];
	n[3]=a[3]+b[3];
	n[4]=a[4]+b[4];
	n[5]=a[5]+b[5];
	n[6]=a[6]+b[6];
	n[7]=a[7]+b[7];
	n[8]=a[8]+b[8];
	n[9]=a[9]+b[9];
	n[10]=a[10]+b[10];
	n[11]=a[11]+b[11];
	n[12]=a[12]+b[12];
	n[0]+=(spint)2u;
	n[4]-=(spint)0x42df89182000000u;
	n[5]-=(spint)0x4cd547794c3adeau;
	n[6]-=(spint)0xb4d8ad873ddc74cu;
	n[7]-=(spint)0xbdb2744acf58202u;
	n[8]-=(spint)0x5c3cc280487ad90u;
	n[9]-=(spint)0x73a2850d3ba2390u;
	n[10]-=(spint)0x49180f1f7575df8u;
	n[11]-=(spint)0x7bf54fba3dbb476u;
	n[12]-=(spint)0x37f4c1bd3808336u;
	carry=prop(n);
	n[0]-=(spint)2u&carry;
	n[4]+=((spint)0x42df89182000000u)&carry;
	n[5]+=((spint)0x4cd547794c3adeau)&carry;
	n[6]+=((spint)0xb4d8ad873ddc74cu)&carry;
	n[7]+=((spint)0xbdb2744acf58202u)&carry;
	n[8]+=((spint)0x5c3cc280487ad90u)&carry;
	n[9]+=((spint)0x73a2850d3ba2390u)&carry;
	n[10]+=((spint)0x49180f1f7575df8u)&carry;
	n[11]+=((spint)0x7bf54fba3dbb476u)&carry;
	n[12]+=((spint)0x37f4c1bd3808336u)&carry;
	(void)prop(n);
}

//Modular subtraction - reduce less than 2p
static void modsub(const spint *a,const spint *b,spint *n) {
	spint carry;
	n[0]=a[0]-b[0];
	n[1]=a[1]-b[1];
	n[2]=a[2]-b[2];
	n[3]=a[3]-b[3];
	n[4]=a[4]-b[4];
	n[5]=a[5]-b[5];
	n[6]=a[6]-b[6];
	n[7]=a[7]-b[7];
	n[8]=a[8]-b[8];
	n[9]=a[9]-b[9];
	n[10]=a[10]-b[10];
	n[11]=a[11]-b[11];
	n[12]=a[12]-b[12];
	carry=prop(n);
	n[0]-=(spint)2u&carry;
	n[4]+=((spint)0x42df89182000000u)&carry;
	n[5]+=((spint)0x4cd547794c3adeau)&carry;
	n[6]+=((spint)0xb4d8ad873ddc74cu)&carry;
	n[7]+=((spint)0xbdb2744acf58202u)&carry;
	n[8]+=((spint)0x5c3cc280487ad90u)&carry;
	n[9]+=((spint)0x73a2850d3ba2390u)&carry;
	n[10]+=((spint)0x49180f1f7575df8u)&carry;
	n[11]+=((spint)0x7bf54fba3dbb476u)&carry;
	n[12]+=((spint)0x37f4c1bd3808336u)&carry;
	(void)prop(n);
}

//Modular negation
static void modneg(const spint *b,spint *n) {
	spint carry;
	n[0]=(spint)0-b[0];
	n[1]=(spint)0-b[1];
	n[2]=(spint)0-b[2];
	n[3]=(spint)0-b[3];
	n[4]=(spint)0-b[4];
	n[5]=(spint)0-b[5];
	n[6]=(spint)0-b[6];
	n[7]=(spint)0-b[7];
	n[8]=(spint)0-b[8];
	n[9]=(spint)0-b[9];
	n[10]=(spint)0-b[10];
	n[11]=(spint)0-b[11];
	n[12]=(spint)0-b[12];
	carry=prop(n);
	n[0]-=(spint)2u&carry;
	n[4]+=((spint)0x42df89182000000u)&carry;
	n[5]+=((spint)0x4cd547794c3adeau)&carry;
	n[6]+=((spint)0xb4d8ad873ddc74cu)&carry;
	n[7]+=((spint)0xbdb2744acf58202u)&carry;
	n[8]+=((spint)0x5c3cc280487ad90u)&carry;
	n[9]+=((spint)0x73a2850d3ba2390u)&carry;
	n[10]+=((spint)0x49180f1f7575df8u)&carry;
	n[11]+=((spint)0x7bf54fba3dbb476u)&carry;
	n[12]+=((spint)0x37f4c1bd3808336u)&carry;
	(void)prop(n);
}

// Overflow limit   = 340282366920938463463374607431768211456
// maximum possible = 5585782468597198479154379959255552271
// Modular multiplication, c=a*b mod 2p
static void modmul(const spint *a,const spint *b,spint *c) {
	dpint t=0;
	spint p4=0x216fc48c1000000u;
	spint p5=0x266aa3bca61d6f5u;
	spint p6=0x5a6c56c39eee3a6u;
	spint p7=0x5ed93a2567ac101u;
	spint p8=0x2e1e6140243d6c8u;
	spint p9=0x39d142869dd11c8u;
	spint p10=0x248c078fbabaefcu;
	spint p11=0x3dfaa7dd1edda3bu;
	spint p12=0x1bfa60de9c0419bu;
	spint q=((spint)1<<59u); // q is unsaturated radix 
	spint mask=(spint)(q-(spint)1);
	t+=(dpint)a[0]*b[0]; spint v0=((spint)t & mask); t>>=59;
	t+=(dpint)a[0]*b[1]; t+=(dpint)a[1]*b[0]; spint v1=((spint)t & mask);  t>>=59;
	t+=(dpint)a[0]*b[2]; t+=(dpint)a[1]*b[1]; t+=(dpint)a[2]*b[0]; spint v2=((spint)t & mask);  t>>=59;
	t+=(dpint)a[0]*b[3]; t+=(dpint)a[1]*b[2]; t+=(dpint)a[2]*b[1]; t+=(dpint)a[3]*b[0]; spint v3=((spint)t & mask);  t>>=59;
	t+=(dpint)a[0]*b[4]; t+=(dpint)a[1]*b[3]; t+=(dpint)a[2]*b[2]; t+=(dpint)a[3]*b[1]; t+=(dpint)a[4]*b[0]; t+=(dpint)v0*(dpint)p4;  spint v4=((spint)t & mask);  t>>=59;
	t+=(dpint)a[0]*b[5]; t+=(dpint)a[1]*b[4]; t+=(dpint)a[2]*b[3]; t+=(dpint)a[3]*b[2]; t+=(dpint)a[4]*b[1]; t+=(dpint)a[5]*b[0]; t+=(dpint)v0*(dpint)p5;  t+=(dpint)v1*(dpint)p4;  spint v5=((spint)t & mask);  t>>=59;
	t+=(dpint)a[0]*b[6]; t+=(dpint)a[1]*b[5]; t+=(dpint)a[2]*b[4]; t+=(dpint)a[3]*b[3]; t+=(dpint)a[4]*b[2]; t+=(dpint)a[5]*b[1]; t+=(dpint)a[6]*b[0]; t+=(dpint)v0*(dpint)p6;  t+=(dpint)v1*(dpint)p5;  t+=(dpint)v2*(dpint)p4;  spint v6=((spint)t & mask);  t>>=59;
	t+=(dpint)a[0]*b[7]; t+=(dpint)a[1]*b[6]; t+=(dpint)a[2]*b[5]; t+=(dpint)a[3]*b[4]; t+=(dpint)a[4]*b[3]; t+=(dpint)a[5]*b[2]; t+=(dpint)a[6]*b[1]; t+=(dpint)a[7]*b[0]; t+=(dpint)v0*(dpint)p7;  t+=(dpint)v1*(dpint)p6;  t+=(dpint)v2*(dpint)p5;  t+=(dpint)v3*(dpint)p4;  spint v7=((spint)t & mask);  t>>=59;
	t+=(dpint)a[0]*b[8]; t+=(dpint)a[1]*b[7]; t+=(dpint)a[2]*b[6]; t+=(dpint)a[3]*b[5]; t+=(dpint)a[4]*b[4]; t+=(dpint)a[5]*b[3]; t+=(dpint)a[6]*b[2]; t+=(dpint)a[7]*b[1]; t+=(dpint)a[8]*b[0]; t+=(dpint)v0*(dpint)p8;  t+=(dpint)v1*(dpint)p7;  t+=(dpint)v2*(dpint)p6;  t+=(dpint)v3*(dpint)p5;  t+=(dpint)v4*(dpint)p4;  spint v8=((spint)t & mask);  t>>=59;
	t+=(dpint)a[0]*b[9]; t+=(dpint)a[1]*b[8]; t+=(dpint)a[2]*b[7]; t+=(dpint)a[3]*b[6]; t+=(dpint)a[4]*b[5]; t+=(dpint)a[5]*b[4]; t+=(dpint)a[6]*b[3]; t+=(dpint)a[7]*b[2]; t+=(dpint)a[8]*b[1]; t+=(dpint)a[9]*b[0]; t+=(dpint)v0*(dpint)p9;  t+=(dpint)v1*(dpint)p8;  t+=(dpint)v2*(dpint)p7;  t+=(dpint)v3*(dpint)p6;  t+=(dpint)v4*(dpint)p5;  t+=(dpint)v5*(dpint)p4;  spint v9=((spint)t & mask);  t>>=59;
	t+=(dpint)a[0]*b[10]; t+=(dpint)a[1]*b[9]; t+=(dpint)a[2]*b[8]; t+=(dpint)a[3]*b[7]; t+=(dpint)a[4]*b[6]; t+=(dpint)a[5]*b[5]; t+=(dpint)a[6]*b[4]; t+=(dpint)a[7]*b[3]; t+=(dpint)a[8]*b[2]; t+=(dpint)a[9]*b[1]; t+=(dpint)a[10]*b[0]; t+=(dpint)v0*(dpint)p10;  t+=(dpint)v1*(dpint)p9;  t+=(dpint)v2*(dpint)p8;  t+=(dpint)v3*(dpint)p7;  t+=(dpint)v4*(dpint)p6;  t+=(dpint)v5*(dpint)p5;  t+=(dpint)v6*(dpint)p4;  spint v10=((spint)t & mask);  t>>=59;
	t+=(dpint)a[0]*b[11]; t+=(dpint)a[1]*b[10]; t+=(dpint)a[2]*b[9]; t+=(dpint)a[3]*b[8]; t+=(dpint)a[4]*b[7]; t+=(dpint)a[5]*b[6]; t+=(dpint)a[6]*b[5]; t+=(dpint)a[7]*b[4]; t+=(dpint)a[8]*b[3]; t+=(dpint)a[9]*b[2]; t+=(dpint)a[10]*b[1]; t+=(dpint)a[11]*b[0]; t+=(dpint)v0*(dpint)p11;  t+=(dpint)v1*(dpint)p10;  t+=(dpint)v2*(dpint)p9;  t+=(dpint)v3*(dpint)p8;  t+=(dpint)v4*(dpint)p7;  t+=(dpint)v5*(dpint)p6;  t+=(dpint)v6*(dpint)p5;  t+=(dpint)v7*(dpint)p4;  spint v11=((spint)t & mask);  t>>=59;
	t+=(dpint)a[0]*b[12]; t+=(dpint)a[1]*b[11]; t+=(dpint)a[2]*b[10]; t+=(dpint)a[3]*b[9]; t+=(dpint)a[4]*b[8]; t+=(dpint)a[5]*b[7]; t+=(dpint)a[6]*b[6]; t+=(dpint)a[7]*b[5]; t+=(dpint)a[8]*b[4]; t+=(dpint)a[9]*b[3]; t+=(dpint)a[10]*b[2]; t+=(dpint)a[11]*b[1]; t+=(dpint)a[12]*b[0]; t+=(dpint)v0*(dpint)p12;  t+=(dpint)v1*(dpint)p11;  t+=(dpint)v2*(dpint)p10;  t+=(dpint)v3*(dpint)p9;  t+=(dpint)v4*(dpint)p8;  t+=(dpint)v5*(dpint)p7;  t+=(dpint)v6*(dpint)p6;  t+=(dpint)v7*(dpint)p5;  t+=(dpint)v8*(dpint)p4;  spint v12=((spint)t & mask);  t>>=59;
	t+=(dpint)a[1]*b[12]; t+=(dpint)a[2]*b[11]; t+=(dpint)a[3]*b[10]; t+=(dpint)a[4]*b[9]; t+=(dpint)a[5]*b[8]; t+=(dpint)a[6]*b[7]; t+=(dpint)a[7]*b[6]; t+=(dpint)a[8]*b[5]; t+=(dpint)a[9]*b[4]; t+=(dpint)a[10]*b[3]; t+=(dpint)a[11]*b[2]; t+=(dpint)a[12]*b[1]; t+=(dpint)v1*(dpint)p12;  t+=(dpint)v2*(dpint)p11;  t+=(dpint)v3*(dpint)p10;  t+=(dpint)v4*(dpint)p9;  t+=(dpint)v5*(dpint)p8;  t+=(dpint)v6*(dpint)p7;  t+=(dpint)v7*(dpint)p6;  t+=(dpint)v8*(dpint)p5;  t+=(dpint)v9*(dpint)p4;  c[0]=((spint)t & mask);  t>>=59;
	t+=(dpint)a[2]*b[12]; t+=(dpint)a[3]*b[11]; t+=(dpint)a[4]*b[10]; t+=(dpint)a[5]*b[9]; t+=(dpint)a[6]*b[8]; t+=(dpint)a[7]*b[7]; t+=(dpint)a[8]*b[6]; t+=(dpint)a[9]*b[5]; t+=(dpint)a[10]*b[4]; t+=(dpint)a[11]*b[3]; t+=(dpint)a[12]*b[2]; t+=(dpint)v2*(dpint)p12;  t+=(dpint)v3*(dpint)p11;  t+=(dpint)v4*(dpint)p10;  t+=(dpint)v5*(dpint)p9;  t+=(dpint)v6*(dpint)p8;  t+=(dpint)v7*(dpint)p7;  t+=(dpint)v8*(dpint)p6;  t+=(dpint)v9*(dpint)p5;  t+=(dpint)v10*(dpint)p4;  c[1]=((spint)t & mask);  t>>=59;
	t+=(dpint)a[3]*b[12]; t+=(dpint)a[4]*b[11]; t+=(dpint)a[5]*b[10]; t+=(dpint)a[6]*b[9]; t+=(dpint)a[7]*b[8]; t+=(dpint)a[8]*b[7]; t+=(dpint)a[9]*b[6]; t+=(dpint)a[10]*b[5]; t+=(dpint)a[11]*b[4]; t+=(dpint)a[12]*b[3]; t+=(dpint)v3*(dpint)p12;  t+=(dpint)v4*(dpint)p11;  t+=(dpint)v5*(dpint)p10;  t+=(dpint)v6*(dpint)p9;  t+=(dpint)v7*(dpint)p8;  t+=(dpint)v8*(dpint)p7;  t+=(dpint)v9*(dpint)p6;  t+=(dpint)v10*(dpint)p5;  t+=(dpint)v11*(dpint)p4;  c[2]=((spint)t & mask);  t>>=59;
	t+=(dpint)a[4]*b[12]; t+=(dpint)a[5]*b[11]; t+=(dpint)a[6]*b[10]; t+=(dpint)a[7]*b[9]; t+=(dpint)a[8]*b[8]; t+=(dpint)a[9]*b[7]; t+=(dpint)a[10]*b[6]; t+=(dpint)a[11]*b[5]; t+=(dpint)a[12]*b[4]; t+=(dpint)v4*(dpint)p12;  t+=(dpint)v5*(dpint)p11;  t+=(dpint)v6*(dpint)p10;  t+=(dpint)v7*(dpint)p9;  t+=(dpint)v8*(dpint)p8;  t+=(dpint)v9*(dpint)p7;  t+=(dpint)v10*(dpint)p6;  t+=(dpint)v11*(dpint)p5;  t+=(dpint)v12*(dpint)p4;  c[3]=((spint)t & mask);  t>>=59;
	t+=(dpint)a[5]*b[12]; t+=(dpint)a[6]*b[11]; t+=(dpint)a[7]*b[10]; t+=(dpint)a[8]*b[9]; t+=(dpint)a[9]*b[8]; t+=(dpint)a[10]*b[7]; t+=(dpint)a[11]*b[6]; t+=(dpint)a[12]*b[5]; t+=(dpint)v5*(dpint)p12;  t+=(dpint)v6*(dpint)p11;  t+=(dpint)v7*(dpint)p10;  t+=(dpint)v8*(dpint)p9;  t+=(dpint)v9*(dpint)p8;  t+=(dpint)v10*(dpint)p7;  t+=(dpint)v11*(dpint)p6;  t+=(dpint)v12*(dpint)p5;  c[4]=((spint)t & mask);  t>>=59;
	t+=(dpint)a[6]*b[12]; t+=(dpint)a[7]*b[11]; t+=(dpint)a[8]*b[10]; t+=(dpint)a[9]*b[9]; t+=(dpint)a[10]*b[8]; t+=(dpint)a[11]*b[7]; t+=(dpint)a[12]*b[6]; t+=(dpint)v6*(dpint)p12;  t+=(dpint)v7*(dpint)p11;  t+=(dpint)v8*(dpint)p10;  t+=(dpint)v9*(dpint)p9;  t+=(dpint)v10*(dpint)p8;  t+=(dpint)v11*(dpint)p7;  t+=(dpint)v12*(dpint)p6;  c[5]=((spint)t & mask);  t>>=59;
	t+=(dpint)a[7]*b[12]; t+=(dpint)a[8]*b[11]; t+=(dpint)a[9]*b[10]; t+=(dpint)a[10]*b[9]; t+=(dpint)a[11]*b[8]; t+=(dpint)a[12]*b[7]; t+=(dpint)v7*(dpint)p12;  t+=(dpint)v8*(dpint)p11;  t+=(dpint)v9*(dpint)p10;  t+=(dpint)v10*(dpint)p9;  t+=(dpint)v11*(dpint)p8;  t+=(dpint)v12*(dpint)p7;  c[6]=((spint)t & mask);  t>>=59;
	t+=(dpint)a[8]*b[12]; t+=(dpint)a[9]*b[11]; t+=(dpint)a[10]*b[10]; t+=(dpint)a[11]*b[9]; t+=(dpint)a[12]*b[8]; t+=(dpint)v8*(dpint)p12;  t+=(dpint)v9*(dpint)p11;  t+=(dpint)v10*(dpint)p10;  t+=(dpint)v11*(dpint)p9;  t+=(dpint)v12*(dpint)p8;  c[7]=((spint)t & mask);  t>>=59;
	t+=(dpint)a[9]*b[12]; t+=(dpint)a[10]*b[11]; t+=(dpint)a[11]*b[10]; t+=(dpint)a[12]*b[9]; t+=(dpint)v9*(dpint)p12;  t+=(dpint)v10*(dpint)p11;  t+=(dpint)v11*(dpint)p10;  t+=(dpint)v12*(dpint)p9;  c[8]=((spint)t & mask);  t>>=59;
	t+=(dpint)a[10]*b[12]; t+=(dpint)a[11]*b[11]; t+=(dpint)a[12]*b[10]; t+=(dpint)v10*(dpint)p12;  t+=(dpint)v11*(dpint)p11;  t+=(dpint)v12*(dpint)p10;  c[9]=((spint)t & mask);  t>>=59;
	t+=(dpint)a[11]*b[12]; t+=(dpint)a[12]*b[11]; t+=(dpint)v11*(dpint)p12;  t+=(dpint)v12*(dpint)p11;  c[10]=((spint)t & mask);  t>>=59;
	t+=(dpint)a[12]*b[12]; t+=(dpint)v12*(dpint)p12;  c[11]=((spint)t & mask);  t>>=59;
	c[12] = (spint)t;
}

// Modular squaring, c=a*a  mod 2p
static void modsqr(const spint *a,spint *c) {
	dpint tot;
	dpint t=0;
	spint p4=0x216fc48c1000000u;
	spint p5=0x266aa3bca61d6f5u;
	spint p6=0x5a6c56c39eee3a6u;
	spint p7=0x5ed93a2567ac101u;
	spint p8=0x2e1e6140243d6c8u;
	spint p9=0x39d142869dd11c8u;
	spint p10=0x248c078fbabaefcu;
	spint p11=0x3dfaa7dd1edda3bu;
	spint p12=0x1bfa60de9c0419bu;
	spint q=((spint)1<<59u); // q is unsaturated radix 
	spint mask=(spint)(q-(spint)1);
	tot=(dpint)a[0]*a[0]; t=tot; spint v0=((spint)t & mask); t>>=59;
	tot=(dpint)a[0]*a[1]; tot*=2; t+=tot;  spint v1=((spint)t & mask); t>>=59;
	tot=(dpint)a[0]*a[2]; tot*=2; tot+=(dpint)a[1]*a[1]; t+=tot;  spint v2=((spint)t & mask); t>>=59;
	tot=(dpint)a[0]*a[3]; tot+=(dpint)a[1]*a[2]; tot*=2; t+=tot;  spint v3=((spint)t & mask); t>>=59;
	tot=(dpint)a[0]*a[4]; tot+=(dpint)a[1]*a[3]; tot*=2; tot+=(dpint)a[2]*a[2]; t+=tot;  t+=(dpint)v0*p4;  spint v4=((spint)t & mask); t>>=59;
	tot=(dpint)a[0]*a[5]; tot+=(dpint)a[1]*a[4]; tot+=(dpint)a[2]*a[3]; tot*=2; t+=tot;  t+=(dpint)v0*p5;  t+=(dpint)v1*p4;  spint v5=((spint)t & mask); t>>=59;
	tot=(dpint)a[0]*a[6]; tot+=(dpint)a[1]*a[5]; tot+=(dpint)a[2]*a[4]; tot*=2; tot+=(dpint)a[3]*a[3]; t+=tot;  t+=(dpint)v0*p6;  t+=(dpint)v1*p5;  t+=(dpint)v2*p4;  spint v6=((spint)t & mask); t>>=59;
	tot=(dpint)a[0]*a[7]; tot+=(dpint)a[1]*a[6]; tot+=(dpint)a[2]*a[5]; tot+=(dpint)a[3]*a[4]; tot*=2; t+=tot;  t+=(dpint)v0*p7;  t+=(dpint)v1*p6;  t+=(dpint)v2*p5;  t+=(dpint)v3*p4;  spint v7=((spint)t & mask); t>>=59;
	tot=(dpint)a[0]*a[8]; tot+=(dpint)a[1]*a[7]; tot+=(dpint)a[2]*a[6]; tot+=(dpint)a[3]*a[5]; tot*=2; tot+=(dpint)a[4]*a[4]; t+=tot;  t+=(dpint)v0*p8;  t+=(dpint)v1*p7;  t+=(dpint)v2*p6;  t+=(dpint)v3*p5;  t+=(dpint)v4*p4;  spint v8=((spint)t & mask); t>>=59;
	tot=(dpint)a[0]*a[9]; tot+=(dpint)a[1]*a[8]; tot+=(dpint)a[2]*a[7]; tot+=(dpint)a[3]*a[6]; tot+=(dpint)a[4]*a[5]; tot*=2; t+=tot;  t+=(dpint)v0*p9;  t+=(dpint)v1*p8;  t+=(dpint)v2*p7;  t+=(dpint)v3*p6;  t+=(dpint)v4*p5;  t+=(dpint)v5*p4;  spint v9=((spint)t & mask); t>>=59;
	tot=(dpint)a[0]*a[10]; tot+=(dpint)a[1]*a[9]; tot+=(dpint)a[2]*a[8]; tot+=(dpint)a[3]*a[7]; tot+=(dpint)a[4]*a[6]; tot*=2; tot+=(dpint)a[5]*a[5]; t+=tot;  t+=(dpint)v0*p10;  t+=(dpint)v1*p9;  t+=(dpint)v2*p8;  t+=(dpint)v3*p7;  t+=(dpint)v4*p6;  t+=(dpint)v5*p5;  t+=(dpint)v6*p4;  spint v10=((spint)t & mask); t>>=59;
	tot=(dpint)a[0]*a[11]; tot+=(dpint)a[1]*a[10]; tot+=(dpint)a[2]*a[9]; tot+=(dpint)a[3]*a[8]; tot+=(dpint)a[4]*a[7]; tot+=(dpint)a[5]*a[6]; tot*=2; t+=tot;  t+=(dpint)v0*p11;  t+=(dpint)v1*p10;  t+=(dpint)v2*p9;  t+=(dpint)v3*p8;  t+=(dpint)v4*p7;  t+=(dpint)v5*p6;  t+=(dpint)v6*p5;  t+=(dpint)v7*p4;  spint v11=((spint)t & mask); t>>=59;
	tot=(dpint)a[0]*a[12]; tot+=(dpint)a[1]*a[11]; tot+=(dpint)a[2]*a[10]; tot+=(dpint)a[3]*a[9]; tot+=(dpint)a[4]*a[8]; tot+=(dpint)a[5]*a[7]; tot*=2; tot+=(dpint)a[6]*a[6]; t+=tot;  t+=(dpint)v0*p12;  t+=(dpint)v1*p11;  t+=(dpint)v2*p10;  t+=(dpint)v3*p9;  t+=(dpint)v4*p8;  t+=(dpint)v5*p7;  t+=(dpint)v6*p6;  t+=(dpint)v7*p5;  t+=(dpint)v8*p4;  spint v12=((spint)t & mask); t>>=59;
	tot=(dpint)a[1]*a[12]; tot+=(dpint)a[2]*a[11]; tot+=(dpint)a[3]*a[10]; tot+=(dpint)a[4]*a[9]; tot+=(dpint)a[5]*a[8]; tot+=(dpint)a[6]*a[7]; tot*=2; t+=tot;  t+=(dpint)v1*p12;  t+=(dpint)v2*p11;  t+=(dpint)v3*p10;  t+=(dpint)v4*p9;  t+=(dpint)v5*p8;  t+=(dpint)v6*p7;  t+=(dpint)v7*p6;  t+=(dpint)v8*p5;  t+=(dpint)v9*p4;  c[0]=((spint)t & mask);  t>>=59;
	tot=(dpint)a[2]*a[12]; tot+=(dpint)a[3]*a[11]; tot+=(dpint)a[4]*a[10]; tot+=(dpint)a[5]*a[9]; tot+=(dpint)a[6]*a[8]; tot*=2; tot+=(dpint)a[7]*a[7]; t+=tot;  t+=(dpint)v2*p12;  t+=(dpint)v3*p11;  t+=(dpint)v4*p10;  t+=(dpint)v5*p9;  t+=(dpint)v6*p8;  t+=(dpint)v7*p7;  t+=(dpint)v8*p6;  t+=(dpint)v9*p5;  t+=(dpint)v10*p4;  c[1]=((spint)t & mask);  t>>=59;
	tot=(dpint)a[3]*a[12]; tot+=(dpint)a[4]*a[11]; tot+=(dpint)a[5]*a[10]; tot+=(dpint)a[6]*a[9]; tot+=(dpint)a[7]*a[8]; tot*=2; t+=tot;  t+=(dpint)v3*p12;  t+=(dpint)v4*p11;  t+=(dpint)v5*p10;  t+=(dpint)v6*p9;  t+=(dpint)v7*p8;  t+=(dpint)v8*p7;  t+=(dpint)v9*p6;  t+=(dpint)v10*p5;  t+=(dpint)v11*p4;  c[2]=((spint)t & mask);  t>>=59;
	tot=(dpint)a[4]*a[12]; tot+=(dpint)a[5]*a[11]; tot+=(dpint)a[6]*a[10]; tot+=(dpint)a[7]*a[9]; tot*=2; tot+=(dpint)a[8]*a[8]; t+=tot;  t+=(dpint)v4*p12;  t+=(dpint)v5*p11;  t+=(dpint)v6*p10;  t+=(dpint)v7*p9;  t+=(dpint)v8*p8;  t+=(dpint)v9*p7;  t+=(dpint)v10*p6;  t+=(dpint)v11*p5;  t+=(dpint)v12*p4;  c[3]=((spint)t & mask);  t>>=59;
	tot=(dpint)a[5]*a[12]; tot+=(dpint)a[6]*a[11]; tot+=(dpint)a[7]*a[10]; tot+=(dpint)a[8]*a[9]; tot*=2; t+=tot;  t+=(dpint)v5*p12;  t+=(dpint)v6*p11;  t+=(dpint)v7*p10;  t+=(dpint)v8*p9;  t+=(dpint)v9*p8;  t+=(dpint)v10*p7;  t+=(dpint)v11*p6;  t+=(dpint)v12*p5;  c[4]=((spint)t & mask);  t>>=59;
	tot=(dpint)a[6]*a[12]; tot+=(dpint)a[7]*a[11]; tot+=(dpint)a[8]*a[10]; tot*=2; tot+=(dpint)a[9]*a[9]; t+=tot;  t+=(dpint)v6*p12;  t+=(dpint)v7*p11;  t+=(dpint)v8*p10;  t+=(dpint)v9*p9;  t+=(dpint)v10*p8;  t+=(dpint)v11*p7;  t+=(dpint)v12*p6;  c[5]=((spint)t & mask);  t>>=59;
	tot=(dpint)a[7]*a[12]; tot+=(dpint)a[8]*a[11]; tot+=(dpint)a[9]*a[10]; tot*=2; t+=tot;  t+=(dpint)v7*p12;  t+=(dpint)v8*p11;  t+=(dpint)v9*p10;  t+=(dpint)v10*p9;  t+=(dpint)v11*p8;  t+=(dpint)v12*p7;  c[6]=((spint)t & mask);  t>>=59;
	tot=(dpint)a[8]*a[12]; tot+=(dpint)a[9]*a[11]; tot*=2; tot+=(dpint)a[10]*a[10]; t+=tot;  t+=(dpint)v8*p12;  t+=(dpint)v9*p11;  t+=(dpint)v10*p10;  t+=(dpint)v11*p9;  t+=(dpint)v12*p8;  c[7]=((spint)t & mask);  t>>=59;
	tot=(dpint)a[9]*a[12]; tot+=(dpint)a[10]*a[11]; tot*=2; t+=tot;  t+=(dpint)v9*p12;  t+=(dpint)v10*p11;  t+=(dpint)v11*p10;  t+=(dpint)v12*p9;  c[8]=((spint)t & mask);  t>>=59;
	tot=(dpint)a[10]*a[12]; tot*=2; tot+=(dpint)a[11]*a[11]; t+=tot;  t+=(dpint)v10*p12;  t+=(dpint)v11*p11;  t+=(dpint)v12*p10;  c[9]=((spint)t & mask);  t>>=59;
	tot=(dpint)a[11]*a[12]; tot*=2; t+=tot;  t+=(dpint)v11*p12;  t+=(dpint)v12*p11;  c[10]=((spint)t & mask);  t>>=59;
	tot=(dpint)a[12]*a[12]; t+=tot;  t+=(dpint)v12*p12;  c[11]=((spint)t & mask);  t>>=59;
	c[12] = (spint)t;
}

//copy
static void modcpy(const spint *a,spint *c) {
	int i;
	for (i=0;i<13;i++) {
		c[i]=a[i];
	}
}

//square n times
static void modnsqr(spint *a,int n) {
	int i;
	for (i=0;i<n;i++) {
		modsqr(a,a);
	}
}

//Calculate progenitor
static void modpro(const spint *w,spint *z) {
	spint x[13];
	spint t0[13];
	spint t1[13];
	spint t2[13];
	spint t3[13];
	spint t4[13];
	spint t5[13];
	spint t6[13];
	spint t7[13];
	spint t8[13];
	spint t9[13];
	spint t10[13];
	spint t11[13];
	spint t12[13];
	spint t13[13];
	spint t14[13];
	spint t15[13];
	spint t16[13];
	spint t17[13];
	spint t18[13];
	spint t19[13];
	spint t20[13];
	spint t21[13];
	spint t22[13];
	spint t23[13];
	spint t24[13];
	spint t25[13];
	spint t26[13];
	spint t27[13];
	spint t28[13];
	spint t29[13];
	modcpy(w,x);
	modsqr(x,t14);
	modmul(x,t14,z);
	modsqr(z,t1);
	modmul(z,t1,t4);
	modmul(x,t4,t0);
	modmul(t1,t0,t8);
	modmul(t14,t8,t2);
	modmul(x,t2,t1);
	modmul(x,t1,t9);
	modmul(z,t9,t10);
	modmul(t14,t10,t5);
	modmul(x,t5,t19);
	modmul(t4,t19,t6);
	modmul(z,t6,t15);
	modmul(t2,t15,t18);
	modmul(t14,t18,t11);
	modmul(t5,t15,t3);
	modmul(t0,t3,t12);
	modmul(t19,t11,t13);
	modmul(t5,t3,t0);
	modmul(t5,t0,t5);
	modmul(t1,t5,t7);
	modmul(t2,t7,t1);
	modmul(t14,t1,t20);
	modmul(t14,t20,t16);
	modmul(t8,t1,t14);
	modmul(t9,t16,t8);
	modmul(t2,t8,t22);
	modmul(t2,t22,t2);
	modmul(t11,t2,t28);
	modmul(t9,t28,t17);
	modmul(t10,t17,t10);
	modmul(t3,t10,t3);
	modmul(t9,t3,t11);
	modmul(t10,t11,t10);
	modmul(t12,t10,t12);
	modmul(t20,t12,t23);
	modmul(t15,t23,t15);
	modmul(t19,t15,t20);
	modmul(t0,t20,t21);
	modmul(t19,t21,t0);
	modmul(t13,t0,t13);
	modmul(t5,t0,t25);
	modmul(t4,t25,t4);
	modmul(t1,t4,t1);
	modmul(t9,t1,t9);
	modmul(t22,t9,t26);
	modmul(t19,t26,t27);
	modmul(t17,t27,t19);
	modmul(t6,t19,t6);
	modmul(t18,t19,t17);
	modmul(t11,t17,t11);
	modmul(t16,t11,t16);
	modmul(t21,t27,t29);
	modmul(t14,t29,t14);
	modmul(t8,t14,t8);
	modmul(t15,t8,t24);
	modmul(t2,t24,t2);
	modmul(t6,t2,t22);
	modmul(t3,t22,t15);
	modmul(t4,t15,t4);
	modmul(t5,t4,t6);
	modmul(t0,t6,t5);
	modmul(t25,t5,t25);
	modmul(t20,t25,t20);
	modmul(t1,t20,t1);
	modmul(t9,t1,t9);
	modmul(t28,t9,t28);
	modmul(t23,t28,t23);
	modmul(t27,t23,t27);
	modmul(t11,t27,t11);
	modmul(t6,t11,t6);
	modmul(t12,t6,t12);
	modmul(t17,t12,t17);
	modmul(t3,t17,t3);
	modmul(t26,t3,t26);
	modmul(t16,t26,t16);
	modmul(t14,t16,t14);
	modmul(t2,t14,t2);
	modmul(t18,t2,t18);
	modmul(t8,t18,t8);
	modmul(t13,t8,t13);
	modmul(t5,t13,t5);
	modmul(t29,t5,t29);
	modmul(t19,t29,t19);
	modmul(t24,t19,t24);
	modmul(t7,t24,t7);
	modmul(t21,t7,t21);
	modmul(t0,t21,t0);
	modnsqr(t29,19);
	modmul(t28,t29,t28);
	modnsqr(t28,22);
	modmul(t27,t28,t27);
	modnsqr(t27,16);
	modmul(t26,t27,t26);
	modnsqr(t26,15);
	modmul(t25,t26,t25);
	modnsqr(t25,19);
	modmul(t24,t25,t24);
	modnsqr(t24,17);
	modmul(t23,t24,t23);
	modnsqr(t23,16);
	modmul(t22,t23,t22);
	modnsqr(t22,19);
	modmul(t21,t22,t21);
	modnsqr(t21,14);
	modmul(t20,t21,t20);
	modnsqr(t20,19);
	modmul(t19,t20,t19);
	modnsqr(t19,20);
	modmul(t18,t19,t18);
	modnsqr(t18,16);
	modmul(t17,t18,t17);
	modnsqr(t17,18);
	modmul(t16,t17,t16);
	modnsqr(t16,13);
	modmul(t15,t16,t15);
	modnsqr(t15,24);
	modmul(t14,t15,t14);
	modnsqr(t14,16);
	modmul(t13,t14,t13);
	modnsqr(t13,16);
	modmul(t12,t13,t12);
	modnsqr(t12,18);
	modmul(t11,t12,t11);
	modnsqr(t11,11);
	modmul(t10,t11,t10);
	modnsqr(t10,21);
	modmul(t9,t10,t9);
	modnsqr(t9,19);
	modmul(t8,t9,t8);
	modnsqr(t8,18);
	modmul(t7,t8,t7);
	modnsqr(t7,15);
	modmul(t6,t7,t6);
	modnsqr(t6,18);
	modmul(t5,t6,t5);
	modnsqr(t5,14);
	modmul(t4,t5,t4);
	modnsqr(t4,19);
	modmul(t3,t4,t3);
	modnsqr(t3,17);
	modmul(t2,t3,t2);
	modnsqr(t2,14);
	modmul(t1,t2,t1);
	modnsqr(t1,22);
	modmul(t0,t1,t1);
	modnsqr(t1,16);
	modmul(t0,t1,t1);
	modnsqr(t1,16);
	modmul(t0,t1,t1);
	modnsqr(t1,16);
	modmul(t0,t1,t1);
	modnsqr(t1,16);
	modmul(t0,t1,t1);
	modnsqr(t1,16);
	modmul(t0,t1,t1);
	modnsqr(t1,16);
	modmul(t0,t1,t1);
	modnsqr(t1,16);
	modmul(t0,t1,t1);
	modnsqr(t1,16);
	modmul(t0,t1,t1);
	modnsqr(t1,16);
	modmul(t0,t1,t1);
	modnsqr(t1,16);
	modmul(t0,t1,t1);
	modnsqr(t1,16);
	modmul(t0,t1,t1);
	modnsqr(t1,16);
	modmul(t0,t1,t1);
	modnsqr(t1,16);
	modmul(t0,t1,t1);
	modnsqr(t1,16);
	modmul(t0,t1,t1);
	modnsqr(t1,16);
	modmul(t0,t1,t0);
	modnsqr(t0,2);
	modmul(z,t0,z);
}

//calculate inverse, provide progenitor h if available
static void modinv(const spint *x,const spint *h,spint *z) {
	spint s[13];
	spint t[13];
	if (h==NULL) {
		modpro(x,t);
	} else {
		modcpy(h,t);
	}
	modcpy(x,s);
	modnsqr(t,2);
	modmul(s,t,z);
}

//Convert m to n-residue form, n=nres(m) 
static void nres(const spint *m,spint *n) {
	const spint c[13]={0x180c230e7f69076u,0x47fd04a11fc0013u,0x60cfd85a629d1bau,0x19aa93d81be1b53u,0x1120977501c33bcu,0x6b88096946ecd83u,0xe11b6769a8e546u,0x1ab98217a3a328du,0x40cbd74fb40d97cu,0x1e61ebb3f742415u,0x92152aa65706feu,0x684a2e244f0a181u,0xebd0e515f57f95u};
	modmul(m,c,n);
}

//Convert n back to normal form, m=redc(n) 
static void redc(const spint *n,spint *m) {
	int i;
	spint c[13];
	c[0]=1;
	for (i=1;i<13;i++) {
		c[i]=0;
	}
	modmul(n,c,m);
	(void)modfsb(m);
}

//is unity?
static int modis1(const spint *a) {
	int i;
	spint c[13];
	spint c0;
	spint d=0;
	redc(a,c);
	for (i=1;i<13;i++) {
		d|=c[i];
	}
	c0=(spint)c[0];
	return ((spint)1 & ((d-(spint)1)>>59u) & (((c0^(spint)1)-(spint)1)>>59u));
}

//is zero?
static int modis0(const spint *a) {
	int i;
	spint c[13];
	spint d=0;
	redc(a,c);
	for (i=0;i<13;i++) {
		d|=c[i];
	}
	return ((spint)1 & ((d-(spint)1)>>59u));
}

//set to zero
static void modzer(spint *a) {
	int i;
	for (i=0;i<13;i++) {
		a[i]=0;
	}
}

//set to one
static void modone(spint *a) {
	int i;
	a[0]=1;
	for (i=1;i<13;i++) {
		a[i]=0;
	}
	nres(a,a);
}

//set to integer
static void modint(int x,spint *a) {
	int i;
	a[0]=(spint)x;
	for (i=1;i<13;i++) {
		a[i]=0;
	}
	nres(a,a);
}

// Modular multiplication by an integer, c=a*b mod 2p
// uses special method for trinomials, otherwise Barrett-Dhem reduction
static void modmli(const spint *a,int b,spint *c) {
	spint p4=0x216fc48c1000000u;
	spint p5=0x266aa3bca61d6f5u;
	spint p6=0x5a6c56c39eee3a6u;
	spint p7=0x5ed93a2567ac101u;
	spint p8=0x2e1e6140243d6c8u;
	spint p9=0x39d142869dd11c8u;
	spint p10=0x248c078fbabaefcu;
	spint p11=0x3dfaa7dd1edda3bu;
	spint p12=0x1bfa60de9c0419bu;
	spint mask=((spint)1<<59u)-(spint)1;
	dpint t=0;
	spint q,h,r=0x92668931e9e43ae;
	t+=(dpint)a[0]*(dpint)b; c[0]=(spint)t & mask; t=t>>59u;
	t+=(dpint)a[1]*(dpint)b; c[1]=(spint)t & mask; t=t>>59u;
	t+=(dpint)a[2]*(dpint)b; c[2]=(spint)t & mask; t=t>>59u;
	t+=(dpint)a[3]*(dpint)b; c[3]=(spint)t & mask; t=t>>59u;
	t+=(dpint)a[4]*(dpint)b; c[4]=(spint)t & mask; t=t>>59u;
	t+=(dpint)a[5]*(dpint)b; c[5]=(spint)t & mask; t=t>>59u;
	t+=(dpint)a[6]*(dpint)b; c[6]=(spint)t & mask; t=t>>59u;
	t+=(dpint)a[7]*(dpint)b; c[7]=(spint)t & mask; t=t>>59u;
	t+=(dpint)a[8]*(dpint)b; c[8]=(spint)t & mask; t=t>>59u;
	t+=(dpint)a[9]*(dpint)b; c[9]=(spint)t & mask; t=t>>59u;
	t+=(dpint)a[10]*(dpint)b; c[10]=(spint)t & mask; t=t>>59u;
	t+=(dpint)a[11]*(dpint)b; c[11]=(spint)t & mask; t=t>>59u;
	t+=(dpint)a[12]*(dpint)b; c[12]=(spint)t;
	
//Barrett-Dhem reduction
	h = (spint)(t>>52u);
	q=(spint)(((dpint)h*(dpint)r)>>64u);
	c[0]+=q;
	t=(dpint)q*(dpint)p4; c[4]-=(spint)t&mask; c[5]-=(spint)(t>>59u);
	t=(dpint)q*(dpint)p5; c[5]-=(spint)t&mask; c[6]-=(spint)(t>>59u);
	t=(dpint)q*(dpint)p6; c[6]-=(spint)t&mask; c[7]-=(spint)(t>>59u);
	t=(dpint)q*(dpint)p7; c[7]-=(spint)t&mask; c[8]-=(spint)(t>>59u);
	t=(dpint)q*(dpint)p8; c[8]-=(spint)t&mask; c[9]-=(spint)(t>>59u);
	t=(dpint)q*(dpint)p9; c[9]-=(spint)t&mask; c[10]-=(spint)(t>>59u);
	t=(dpint)q*(dpint)p10; c[10]-=(spint)t&mask; c[11]-=(spint)(t>>59u);
	t=(dpint)q*(dpint)p11; c[11]-=(spint)t&mask; c[12]-=(spint)(t>>59u);
	c[12]-=q*p12;
	(void)prop(c);
}

//Test for quadratic residue 
static int modqr(const spint *h,const spint *x) {
	spint r[13];
	if (h==NULL) {
		modpro(x,r);
		modsqr(r,r);
	} else {
		modsqr(h,r);
	}
	modmul(r,x,r);
	return modis1(r) | modis0(x);
}

//conditional move g to f if d=1
//strongly recommend inlining be disabled using compiler specific syntax
static void __attribute__ ((noinline)) modcmv(int b,const spint *g,volatile spint *f) {
	int i;
	spint c0,c1,s,t,w,aux;
	static spint R=0;
	R+=0x3cc3c33c5aa5a55au;
	w=R;
	c0=(~b)&(w+1);
	c1=b+w;
	for (i=0;i<13;i++) {
		s=g[i]; t=f[i];
		f[i] = aux = c0*t+c1*s;
		f[i] = aux - w*(t+s);
	}
}

//conditional swap g and f if d=1
//strongly recommend inlining be disabled using compiler specific syntax
static void __attribute__ ((noinline)) modcsw(int b,volatile spint *g,volatile spint *f) {
	int i;
	spint c0,c1,s,t,w,v,aux;
	static spint R=0;
	R+=0x3cc3c33c5aa5a55au;
	w=R;
	c0=(~b)&(w+1);
	c1=b+w;
	for (i=0;i<13;i++) {
		s=g[i]; t=f[i];
		v=w*(t+s);
		f[i] = aux = c0*t+c1*s;
		f[i] = aux - v;
		g[i] = aux = c0*s+c1*t;
		g[i] = aux - v;
	}
}

//Modular square root, provide progenitor h if available, NULL if not
static void modsqrt(const spint *x,const spint *h,spint *r) {
	spint s[13];
	spint y[13];
	if (h==NULL) {
		modpro(x,y);
	} else {
		modcpy(h,y);
	}
	modmul(y,x,s);
	modcpy(s,r);
}

//shift left by less than a word
static void modshl(unsigned int n,spint *a) {
	int i;
	a[12]=((a[12]<<n)) + (a[11]>>(59u-n));
	for (i=11;i>0;i--) {
		a[i]=((a[i]<<n)&(spint)0x7ffffffffffffff) + (a[i-1]>>(59u-n));
	}
	a[0]=(a[0]<<n)&(spint)0x7ffffffffffffff;
}

//shift right by less than a word. Return shifted out part
static int modshr(unsigned int n,spint *a) {
	int i;
	spint r=a[0]&(((spint)1<<n)-(spint)1);
	for (i=0;i<12;i++) {
		a[i]=(a[i]>>n) + ((a[i+1]<<(59u-n))&(spint)0x7ffffffffffffff);
	}
	a[12]=a[12]>>n;
	return r;
}

//divide by 2. Shift right 1 bit (or add p and shift right one bit)
static void modhaf(spint *n) {
	int lsb;
	spint t[13];
	(void)prop(n);
	modcpy(n,t);
	lsb=modshr(1,t);
	n[0]-=(spint)1;
	n[4]+=((spint)0x216fc48c1000000u);
	n[5]+=((spint)0x266aa3bca61d6f5u);
	n[6]+=((spint)0x5a6c56c39eee3a6u);
	n[7]+=((spint)0x5ed93a2567ac101u);
	n[8]+=((spint)0x2e1e6140243d6c8u);
	n[9]+=((spint)0x39d142869dd11c8u);
	n[10]+=((spint)0x248c078fbabaefcu);
	n[11]+=((spint)0x3dfaa7dd1edda3bu);
	n[12]+=((spint)0x1bfa60de9c0419bu);
	(void)prop(n);
	modshr(1,n);
	modcmv(1-lsb,t,n);
}

//set a= 2^r
static void mod2r(unsigned int r,spint *a) {
	unsigned int n=r/59u;
	unsigned int m=r%59u;
	modzer(a);
	if (r>=96*8) return;
	a[n]=1; a[n]<<=m;
nres(a,a);
}

//export to byte array
static void modexp(const spint *a,char *b) {
	int i;
	spint c[13];
	redc(a,c);
	for (i=95;i>=0;i--) {
		b[i]=c[0]&(spint)0xff;
		(void)modshr(8,c);
	}
}

//import from byte array
//returns 1 if in range, else 0
static int modimp(const char *b, spint *a) {
	int i,res;
	for (i=0;i<13;i++) {
		a[i]=0;
	}
	for (i=0;i<96;i++) {
		modshl(8,a);
		a[0]+=(spint)(unsigned char)b[i];
	}
	res=(int)modfsb(a);
	nres(a,a);
	return res;
}

//determine sign
static int modsign(const spint *a) {
	spint c[13];
	redc(a,c);
	return c[0]%2;
}

//return true if equal
static int modcmp(const spint *a,const spint *b) {
	spint c[13],d[13];
	int i,eq=1;
	redc(a,c);
	redc(b,d);
	for (i=0;i<13;i++) {
		eq&=(((c[i]^d[i])-1)>>59)&1;
	}
	return eq;
}

