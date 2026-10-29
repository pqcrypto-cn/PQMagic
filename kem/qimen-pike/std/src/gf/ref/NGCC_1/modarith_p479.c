
//Automatically generated modular arithmetic C code
//Command line : python monty.py 64 0x588ee91ac23ef552f7bea02286b19c0bf3bb9a90588643dadd9997fbe0daea16974b919e94cbe0b3ffffffffffffffffffffffffffffffffffffffff
//Python Script by Mike Scott (Technology Innovation Institute, UAE, 2025)

#include <stdio.h>
#include <stdint.h>

#define sspint int64_t
#define spint uint64_t
#define dpint __uint128_t
#define sdpint __int128_t
#define Wordlength 64
#define Nlimbs 8
#define Radix 61
#define Nbits 479
#define Nbytes 60

#define MONTGOMERY
//propagate carries
static spint inline prop(spint *n) {
	int i;
	spint mask=((spint)1<<61u)-(spint)1;
	sspint carry=(sspint)n[0];
	carry>>=61u;
	n[0]&=mask;
	for (i=1;i<7;i++) {
		carry+=(sspint)n[i];
		n[i] = (spint)carry & mask;
		carry>>=61u;
	}
	n[7]+=(spint)carry;
	return -((n[7]>>1)>>62u);
}

//propagate carries and add p if negative, propagate carries again
static spint inline flatten(spint *n) {
	spint carry=prop(n);
	n[0]-=(spint)1u&carry;
	n[2]+=((spint)0x12f82d0000000000u)&carry;
	n[3]+=((spint)0x15d42d2e97233d29u)&carry;
	n[4]+=((spint)0x43dadd9997fbe0du)&carry;
	n[5]+=((spint)0xe05f9ddcd482c43u)&carry;
	n[6]+=((spint)0x154bdefa808a1ac6u)&carry;
	n[7]+=((spint)0xb11dd235847deu)&carry;
	(void)prop(n);
	return (carry&1);
}

//Montgomery final subtract
static spint inline modfsb(spint *n) {
	n[0]+=(spint)1u;
	n[2]-=(spint)0x12f82d0000000000u;
	n[3]-=(spint)0x15d42d2e97233d29u;
	n[4]-=(spint)0x43dadd9997fbe0du;
	n[5]-=(spint)0xe05f9ddcd482c43u;
	n[6]-=(spint)0x154bdefa808a1ac6u;
	n[7]-=(spint)0xb11dd235847deu;
	return flatten(n);
}

//Modular addition - reduce less than 2p
static void inline modadd(const spint *a,const spint *b,spint *n) {
	spint carry;
	n[0]=a[0]+b[0];
	n[1]=a[1]+b[1];
	n[2]=a[2]+b[2];
	n[3]=a[3]+b[3];
	n[4]=a[4]+b[4];
	n[5]=a[5]+b[5];
	n[6]=a[6]+b[6];
	n[7]=a[7]+b[7];
	n[0]+=(spint)2u;
	n[2]-=(spint)0x25f05a0000000000u;
	n[3]-=(spint)0x2ba85a5d2e467a52u;
	n[4]-=(spint)0x87b5bb332ff7c1au;
	n[5]-=(spint)0x1c0bf3bb9a905886u;
	n[6]-=(spint)0x2a97bdf50114358cu;
	n[7]-=(spint)0x1623ba46b08fbcu;
	carry=prop(n);
	n[0]-=(spint)2u&carry;
	n[2]+=((spint)0x25f05a0000000000u)&carry;
	n[3]+=((spint)0x2ba85a5d2e467a52u)&carry;
	n[4]+=((spint)0x87b5bb332ff7c1au)&carry;
	n[5]+=((spint)0x1c0bf3bb9a905886u)&carry;
	n[6]+=((spint)0x2a97bdf50114358cu)&carry;
	n[7]+=((spint)0x1623ba46b08fbcu)&carry;
	(void)prop(n);
}

//Modular subtraction - reduce less than 2p
static void inline modsub(const spint *a,const spint *b,spint *n) {
	spint carry;
	n[0]=a[0]-b[0];
	n[1]=a[1]-b[1];
	n[2]=a[2]-b[2];
	n[3]=a[3]-b[3];
	n[4]=a[4]-b[4];
	n[5]=a[5]-b[5];
	n[6]=a[6]-b[6];
	n[7]=a[7]-b[7];
	carry=prop(n);
	n[0]-=(spint)2u&carry;
	n[2]+=((spint)0x25f05a0000000000u)&carry;
	n[3]+=((spint)0x2ba85a5d2e467a52u)&carry;
	n[4]+=((spint)0x87b5bb332ff7c1au)&carry;
	n[5]+=((spint)0x1c0bf3bb9a905886u)&carry;
	n[6]+=((spint)0x2a97bdf50114358cu)&carry;
	n[7]+=((spint)0x1623ba46b08fbcu)&carry;
	(void)prop(n);
}

//Modular negation
static void inline modneg(const spint *b,spint *n) {
	spint carry;
	n[0]=(spint)0-b[0];
	n[1]=(spint)0-b[1];
	n[2]=(spint)0-b[2];
	n[3]=(spint)0-b[3];
	n[4]=(spint)0-b[4];
	n[5]=(spint)0-b[5];
	n[6]=(spint)0-b[6];
	n[7]=(spint)0-b[7];
	carry=prop(n);
	n[0]-=(spint)2u&carry;
	n[2]+=((spint)0x25f05a0000000000u)&carry;
	n[3]+=((spint)0x2ba85a5d2e467a52u)&carry;
	n[4]+=((spint)0x87b5bb332ff7c1au)&carry;
	n[5]+=((spint)0x1c0bf3bb9a905886u)&carry;
	n[6]+=((spint)0x2a97bdf50114358cu)&carry;
	n[7]+=((spint)0x1623ba46b08fbcu)&carry;
	(void)prop(n);
}

// Overflow limit   = 340282366920938463463374607431768211456
// maximum possible = 55894393028828081756109311136385627627
// Modular multiplication, c=a*b mod 2p
static void inline modmul(const spint *a,const spint *b,spint *c) {
	dpint t=0;
	spint p2=0x12f82d0000000000u;
	spint p3=0x15d42d2e97233d29u;
	spint p4=0x43dadd9997fbe0du;
	spint p5=0xe05f9ddcd482c43u;
	spint p6=0x154bdefa808a1ac6u;
	spint p7=0xb11dd235847deu;
	spint q=((spint)1<<61u); // q is unsaturated radix 
	spint mask=(spint)(q-(spint)1);
	t+=(dpint)a[0]*b[0]; spint v0=((spint)t & mask); t>>=61;
	t+=(dpint)a[0]*b[1]; t+=(dpint)a[1]*b[0]; spint v1=((spint)t & mask);  t>>=61;
	t+=(dpint)a[0]*b[2]; t+=(dpint)a[1]*b[1]; t+=(dpint)a[2]*b[0]; t+=(dpint)v0*(dpint)p2;  spint v2=((spint)t & mask);  t>>=61;
	t+=(dpint)a[0]*b[3]; t+=(dpint)a[1]*b[2]; t+=(dpint)a[2]*b[1]; t+=(dpint)a[3]*b[0]; t+=(dpint)v0*(dpint)p3;  t+=(dpint)v1*(dpint)p2;  spint v3=((spint)t & mask);  t>>=61;
	t+=(dpint)a[0]*b[4]; t+=(dpint)a[1]*b[3]; t+=(dpint)a[2]*b[2]; t+=(dpint)a[3]*b[1]; t+=(dpint)a[4]*b[0]; t+=(dpint)v0*(dpint)p4;  t+=(dpint)v1*(dpint)p3;  t+=(dpint)v2*(dpint)p2;  spint v4=((spint)t & mask);  t>>=61;
	t+=(dpint)a[0]*b[5]; t+=(dpint)a[1]*b[4]; t+=(dpint)a[2]*b[3]; t+=(dpint)a[3]*b[2]; t+=(dpint)a[4]*b[1]; t+=(dpint)a[5]*b[0]; t+=(dpint)v0*(dpint)p5;  t+=(dpint)v1*(dpint)p4;  t+=(dpint)v2*(dpint)p3;  t+=(dpint)v3*(dpint)p2;  spint v5=((spint)t & mask);  t>>=61;
	t+=(dpint)a[0]*b[6]; t+=(dpint)a[1]*b[5]; t+=(dpint)a[2]*b[4]; t+=(dpint)a[3]*b[3]; t+=(dpint)a[4]*b[2]; t+=(dpint)a[5]*b[1]; t+=(dpint)a[6]*b[0]; t+=(dpint)v0*(dpint)p6;  t+=(dpint)v1*(dpint)p5;  t+=(dpint)v2*(dpint)p4;  t+=(dpint)v3*(dpint)p3;  t+=(dpint)v4*(dpint)p2;  spint v6=((spint)t & mask);  t>>=61;
	t+=(dpint)a[0]*b[7]; t+=(dpint)a[1]*b[6]; t+=(dpint)a[2]*b[5]; t+=(dpint)a[3]*b[4]; t+=(dpint)a[4]*b[3]; t+=(dpint)a[5]*b[2]; t+=(dpint)a[6]*b[1]; t+=(dpint)a[7]*b[0]; t+=(dpint)v0*(dpint)p7;  t+=(dpint)v1*(dpint)p6;  t+=(dpint)v2*(dpint)p5;  t+=(dpint)v3*(dpint)p4;  t+=(dpint)v4*(dpint)p3;  t+=(dpint)v5*(dpint)p2;  spint v7=((spint)t & mask);  t>>=61;
	t+=(dpint)a[1]*b[7]; t+=(dpint)a[2]*b[6]; t+=(dpint)a[3]*b[5]; t+=(dpint)a[4]*b[4]; t+=(dpint)a[5]*b[3]; t+=(dpint)a[6]*b[2]; t+=(dpint)a[7]*b[1]; t+=(dpint)v1*(dpint)p7;  t+=(dpint)v2*(dpint)p6;  t+=(dpint)v3*(dpint)p5;  t+=(dpint)v4*(dpint)p4;  t+=(dpint)v5*(dpint)p3;  t+=(dpint)v6*(dpint)p2;  c[0]=((spint)t & mask);  t>>=61;
	t+=(dpint)a[2]*b[7]; t+=(dpint)a[3]*b[6]; t+=(dpint)a[4]*b[5]; t+=(dpint)a[5]*b[4]; t+=(dpint)a[6]*b[3]; t+=(dpint)a[7]*b[2]; t+=(dpint)v2*(dpint)p7;  t+=(dpint)v3*(dpint)p6;  t+=(dpint)v4*(dpint)p5;  t+=(dpint)v5*(dpint)p4;  t+=(dpint)v6*(dpint)p3;  t+=(dpint)v7*(dpint)p2;  c[1]=((spint)t & mask);  t>>=61;
	t+=(dpint)a[3]*b[7]; t+=(dpint)a[4]*b[6]; t+=(dpint)a[5]*b[5]; t+=(dpint)a[6]*b[4]; t+=(dpint)a[7]*b[3]; t+=(dpint)v3*(dpint)p7;  t+=(dpint)v4*(dpint)p6;  t+=(dpint)v5*(dpint)p5;  t+=(dpint)v6*(dpint)p4;  t+=(dpint)v7*(dpint)p3;  c[2]=((spint)t & mask);  t>>=61;
	t+=(dpint)a[4]*b[7]; t+=(dpint)a[5]*b[6]; t+=(dpint)a[6]*b[5]; t+=(dpint)a[7]*b[4]; t+=(dpint)v4*(dpint)p7;  t+=(dpint)v5*(dpint)p6;  t+=(dpint)v6*(dpint)p5;  t+=(dpint)v7*(dpint)p4;  c[3]=((spint)t & mask);  t>>=61;
	t+=(dpint)a[5]*b[7]; t+=(dpint)a[6]*b[6]; t+=(dpint)a[7]*b[5]; t+=(dpint)v5*(dpint)p7;  t+=(dpint)v6*(dpint)p6;  t+=(dpint)v7*(dpint)p5;  c[4]=((spint)t & mask);  t>>=61;
	t+=(dpint)a[6]*b[7]; t+=(dpint)a[7]*b[6]; t+=(dpint)v6*(dpint)p7;  t+=(dpint)v7*(dpint)p6;  c[5]=((spint)t & mask);  t>>=61;
	t+=(dpint)a[7]*b[7]; t+=(dpint)v7*(dpint)p7;  c[6]=((spint)t & mask);  t>>=61;
	c[7] = (spint)t;
}

// Modular squaring, c=a*a  mod 2p
static void inline modsqr(const spint *a,spint *c) {
	dpint tot;
	dpint t=0;
	spint p2=0x12f82d0000000000u;
	spint p3=0x15d42d2e97233d29u;
	spint p4=0x43dadd9997fbe0du;
	spint p5=0xe05f9ddcd482c43u;
	spint p6=0x154bdefa808a1ac6u;
	spint p7=0xb11dd235847deu;
	spint q=((spint)1<<61u); // q is unsaturated radix 
	spint mask=(spint)(q-(spint)1);
	tot=(dpint)a[0]*a[0]; t=tot; spint v0=((spint)t & mask); t>>=61;
	tot=(dpint)a[0]*a[1]; tot*=2; t+=tot;  spint v1=((spint)t & mask); t>>=61;
	tot=(dpint)a[0]*a[2]; tot*=2; tot+=(dpint)a[1]*a[1]; t+=tot;  t+=(dpint)v0*p2;  spint v2=((spint)t & mask); t>>=61;
	tot=(dpint)a[0]*a[3]; tot+=(dpint)a[1]*a[2]; tot*=2; t+=tot;  t+=(dpint)v0*p3;  t+=(dpint)v1*p2;  spint v3=((spint)t & mask); t>>=61;
	tot=(dpint)a[0]*a[4]; tot+=(dpint)a[1]*a[3]; tot*=2; tot+=(dpint)a[2]*a[2]; t+=tot;  t+=(dpint)v0*p4;  t+=(dpint)v1*p3;  t+=(dpint)v2*p2;  spint v4=((spint)t & mask); t>>=61;
	tot=(dpint)a[0]*a[5]; tot+=(dpint)a[1]*a[4]; tot+=(dpint)a[2]*a[3]; tot*=2; t+=tot;  t+=(dpint)v0*p5;  t+=(dpint)v1*p4;  t+=(dpint)v2*p3;  t+=(dpint)v3*p2;  spint v5=((spint)t & mask); t>>=61;
	tot=(dpint)a[0]*a[6]; tot+=(dpint)a[1]*a[5]; tot+=(dpint)a[2]*a[4]; tot*=2; tot+=(dpint)a[3]*a[3]; t+=tot;  t+=(dpint)v0*p6;  t+=(dpint)v1*p5;  t+=(dpint)v2*p4;  t+=(dpint)v3*p3;  t+=(dpint)v4*p2;  spint v6=((spint)t & mask); t>>=61;
	tot=(dpint)a[0]*a[7]; tot+=(dpint)a[1]*a[6]; tot+=(dpint)a[2]*a[5]; tot+=(dpint)a[3]*a[4]; tot*=2; t+=tot;  t+=(dpint)v0*p7;  t+=(dpint)v1*p6;  t+=(dpint)v2*p5;  t+=(dpint)v3*p4;  t+=(dpint)v4*p3;  t+=(dpint)v5*p2;  spint v7=((spint)t & mask); t>>=61;
	tot=(dpint)a[1]*a[7]; tot+=(dpint)a[2]*a[6]; tot+=(dpint)a[3]*a[5]; tot*=2; tot+=(dpint)a[4]*a[4]; t+=tot;  t+=(dpint)v1*p7;  t+=(dpint)v2*p6;  t+=(dpint)v3*p5;  t+=(dpint)v4*p4;  t+=(dpint)v5*p3;  t+=(dpint)v6*p2;  c[0]=((spint)t & mask);  t>>=61;
	tot=(dpint)a[2]*a[7]; tot+=(dpint)a[3]*a[6]; tot+=(dpint)a[4]*a[5]; tot*=2; t+=tot;  t+=(dpint)v2*p7;  t+=(dpint)v3*p6;  t+=(dpint)v4*p5;  t+=(dpint)v5*p4;  t+=(dpint)v6*p3;  t+=(dpint)v7*p2;  c[1]=((spint)t & mask);  t>>=61;
	tot=(dpint)a[3]*a[7]; tot+=(dpint)a[4]*a[6]; tot*=2; tot+=(dpint)a[5]*a[5]; t+=tot;  t+=(dpint)v3*p7;  t+=(dpint)v4*p6;  t+=(dpint)v5*p5;  t+=(dpint)v6*p4;  t+=(dpint)v7*p3;  c[2]=((spint)t & mask);  t>>=61;
	tot=(dpint)a[4]*a[7]; tot+=(dpint)a[5]*a[6]; tot*=2; t+=tot;  t+=(dpint)v4*p7;  t+=(dpint)v5*p6;  t+=(dpint)v6*p5;  t+=(dpint)v7*p4;  c[3]=((spint)t & mask);  t>>=61;
	tot=(dpint)a[5]*a[7]; tot*=2; tot+=(dpint)a[6]*a[6]; t+=tot;  t+=(dpint)v5*p7;  t+=(dpint)v6*p6;  t+=(dpint)v7*p5;  c[4]=((spint)t & mask);  t>>=61;
	tot=(dpint)a[6]*a[7]; tot*=2; t+=tot;  t+=(dpint)v6*p7;  t+=(dpint)v7*p6;  c[5]=((spint)t & mask);  t>>=61;
	tot=(dpint)a[7]*a[7]; t+=tot;  t+=(dpint)v7*p7;  c[6]=((spint)t & mask);  t>>=61;
	c[7] = (spint)t;
}

//copy
static void inline modcpy(const spint *a,spint *c) {
	int i;
	for (i=0;i<8;i++) {
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
	spint x[8];
	spint t0[8];
	spint t1[8];
	spint t2[8];
	spint t3[8];
	spint t4[8];
	spint t5[8];
	spint t6[8];
	spint t7[8];
	spint t8[8];
	spint t9[8];
	spint t10[8];
	spint t11[8];
	spint t12[8];
	spint t13[8];
	spint t14[8];
	spint t15[8];
	spint t16[8];
	spint t17[8];
	spint t18[8];
	spint t19[8];
	modcpy(w,x);
	modsqr(x,t0);
	modsqr(t0,t7);
	modmul(t0,t7,t4);
	modmul(x,t4,t8);
	modmul(t4,t8,t3);
	modmul(x,t3,z);
	modmul(t0,z,t9);
	modsqr(t3,t0);
	modmul(t3,t9,t2);
	modmul(t8,t2,t10);
	modmul(t4,t10,t5);
	modmul(t7,t5,t14);
	modmul(z,t14,t6);
	modmul(t3,t6,t1);
	modmul(t3,t1,t3);
	modmul(t10,t3,t11);
	modmul(t10,t11,t18);
	modmul(t7,t18,t12);
	modmul(z,t18,t7);
	modmul(z,t7,z);
	modmul(t9,z,t9);
	modmul(t8,t9,t15);
	modmul(t5,t7,t17);
	modmul(t5,t17,t13);
	modmul(t1,t13,t1);
	modmul(t7,t13,t10);
	modmul(t11,t1,t16);
	modmul(t0,t10,t8);
	modmul(t4,t8,t4);
	modmul(t5,t16,t5);
	modmul(t15,t5,t15);
	modmul(t18,t15,t18);
	modmul(t12,t18,t12);
	modmul(t7,t12,t7);
	modmul(t14,t7,t14);
	modmul(t0,t14,t0);
	modmul(t13,t0,t13);
	modmul(t5,t13,t5);
	modmul(t2,t5,t2);
	modmul(t3,t2,t3);
	modmul(t10,t3,t10);
	modmul(t1,t10,t1);
	modmul(t16,t1,t16);
	modmul(t15,t16,t15);
	modmul(z,t15,z);
	modmul(t9,z,t9);
	modmul(t4,t9,t4);
	modmul(t6,t4,t6);
	modmul(t17,t6,t17);
	modmul(t18,t17,t18);
	modsqr(t18,t19);
	modmul(t1,t19,t1);
	modmul(t13,t1,t13);
	modmul(t11,t13,t11);
	modmul(t9,t11,t9);
	modmul(t3,t9,t3);
	modmul(t4,t3,t4);
	modmul(t10,t4,t10);
	modmul(t16,t10,t16);
	modmul(t8,t16,t8);
	modmul(t6,t8,t6);
	modmul(t18,t6,t18);
	modmul(t2,t18,t2);
	modmul(t0,t2,t0);
	modmul(t17,t0,t17);
	modmul(t12,t17,t12);
	modmul(t7,t12,t7);
	modmul(t15,t7,t15);
	modmul(t14,t15,t14);
	modmul(z,t14,z);
	modnsqr(t18,16);
	modmul(t17,t18,t17);
	modnsqr(t17,16);
	modmul(t16,t17,t16);
	modnsqr(t16,16);
	modmul(t15,t16,t15);
	modnsqr(t15,16);
	modmul(t14,t15,t14);
	modnsqr(t14,16);
	modmul(t13,t14,t13);
	modnsqr(t13,20);
	modmul(t12,t13,t12);
	modnsqr(t12,15);
	modmul(t11,t12,t11);
	modnsqr(t11,17);
	modmul(t10,t11,t10);
	modnsqr(t10,16);
	modmul(t9,t10,t9);
	modnsqr(t9,19);
	modmul(t8,t9,t8);
	modnsqr(t8,16);
	modmul(t7,t8,t7);
	modnsqr(t7,16);
	modmul(t6,t7,t6);
	modnsqr(t6,11);
	modmul(t5,t6,t5);
	modnsqr(t5,20);
	modmul(t4,t5,t4);
	modnsqr(t4,19);
	modmul(t3,t4,t3);
	modnsqr(t3,18);
	modmul(t2,t3,t2);
	modnsqr(t2,14);
	modmul(t1,t2,t1);
	modnsqr(t1,18);
	modmul(t0,t1,t0);
	modnsqr(t0,18);
	modmul(z,t0,t0);
	modnsqr(t0,16);
	modmul(z,t0,t0);
	modnsqr(t0,16);
	modmul(z,t0,t0);
	modnsqr(t0,16);
	modmul(z,t0,t0);
	modnsqr(t0,16);
	modmul(z,t0,t0);
	modnsqr(t0,16);
	modmul(z,t0,t0);
	modnsqr(t0,16);
	modmul(z,t0,t0);
	modnsqr(t0,16);
	modmul(z,t0,t0);
	modnsqr(t0,16);
	modmul(z,t0,t0);
	modnsqr(t0,16);
	modmul(z,t0,z);
}

//calculate inverse, provide progenitor h if available
static void modinv(const spint *x,const spint *h,spint *z) {
	spint s[8];
	spint t[8];
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
	const spint c[8]={0x72fe92c75bcf3afu,0x1fa884bc6a6ec8e1u,0x13d1d249ce5b7df7u,0xcca7b7b103e6638u,0x16a216039935291cu,0xff00aba2e59033eu,0x129266664466c590u,0x379db34565d55u};
	modmul(m,c,n);
}

//Convert n back to normal form, m=redc(n) 
static void redc(const spint *n,spint *m) {
	int i;
	spint c[8];
	c[0]=1;
	for (i=1;i<8;i++) {
		c[i]=0;
	}
	modmul(n,c,m);
	(void)modfsb(m);
}

//is unity?
static int modis1(const spint *a) {
	int i;
	spint c[8];
	spint c0;
	spint d=0;
	redc(a,c);
	for (i=1;i<8;i++) {
		d|=c[i];
	}
	c0=(spint)c[0];
	return ((spint)1 & ((d-(spint)1)>>61u) & (((c0^(spint)1)-(spint)1)>>61u));
}

//is zero?
static int modis0(const spint *a) {
	int i;
	spint c[8];
	spint d=0;
	redc(a,c);
	for (i=0;i<8;i++) {
		d|=c[i];
	}
	return ((spint)1 & ((d-(spint)1)>>61u));
}

//set to zero
static void modzer(spint *a) {
	int i;
	for (i=0;i<8;i++) {
		a[i]=0;
	}
}

//set to one
static void modone(spint *a) {
	int i;
	a[0]=1;
	for (i=1;i<8;i++) {
		a[i]=0;
	}
	nres(a,a);
}

//set to integer
static void modint(int x,spint *a) {
	int i;
	a[0]=(spint)x;
	for (i=1;i<8;i++) {
		a[i]=0;
	}
	nres(a,a);
}

// Modular multiplication by an integer, c=a*b mod 2p
// uses special method for trinomials, otherwise Barrett-Dhem reduction
static void inline modmli(const spint *a,int b,spint *c) {
	spint p2=0x12f82d0000000000u;
	spint p3=0x15d42d2e97233d29u;
	spint p4=0x43dadd9997fbe0du;
	spint p5=0xe05f9ddcd482c43u;
	spint p6=0x154bdefa808a1ac6u;
	spint p7=0xb11dd235847deu;
	spint mask=((spint)1<<61u)-(spint)1;
	dpint t=0;
	spint q,h,r=0x2e408617725561d5;
	t+=(dpint)a[0]*(dpint)b; c[0]=(spint)t & mask; t=t>>61u;
	t+=(dpint)a[1]*(dpint)b; c[1]=(spint)t & mask; t=t>>61u;
	t+=(dpint)a[2]*(dpint)b; c[2]=(spint)t & mask; t=t>>61u;
	t+=(dpint)a[3]*(dpint)b; c[3]=(spint)t & mask; t=t>>61u;
	t+=(dpint)a[4]*(dpint)b; c[4]=(spint)t & mask; t=t>>61u;
	t+=(dpint)a[5]*(dpint)b; c[5]=(spint)t & mask; t=t>>61u;
	t+=(dpint)a[6]*(dpint)b; c[6]=(spint)t & mask; t=t>>61u;
	t+=(dpint)a[7]*(dpint)b; c[7]=(spint)t;
	
//Barrett-Dhem reduction
	h = (spint)(t>>49u);
	q=(spint)(((dpint)h*(dpint)r)>>64u);
	c[0]+=q;
	t=(dpint)q*(dpint)p2; c[2]-=(spint)t&mask; c[3]-=(spint)(t>>61u);
	t=(dpint)q*(dpint)p3; c[3]-=(spint)t&mask; c[4]-=(spint)(t>>61u);
	t=(dpint)q*(dpint)p4; c[4]-=(spint)t&mask; c[5]-=(spint)(t>>61u);
	t=(dpint)q*(dpint)p5; c[5]-=(spint)t&mask; c[6]-=(spint)(t>>61u);
	t=(dpint)q*(dpint)p6; c[6]-=(spint)t&mask; c[7]-=(spint)(t>>61u);
	c[7]-=q*p7;
	(void)prop(c);
}

//Test for quadratic residue 
static int modqr(const spint *h,const spint *x) {
	spint r[8];
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
	for (i=0;i<8;i++) {
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
	for (i=0;i<8;i++) {
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
	spint s[8];
	spint y[8];
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
	a[7]=((a[7]<<n)) + (a[6]>>(61u-n));
	for (i=6;i>0;i--) {
		a[i]=((a[i]<<n)&(spint)0x1fffffffffffffff) + (a[i-1]>>(61u-n));
	}
	a[0]=(a[0]<<n)&(spint)0x1fffffffffffffff;
}

//shift right by less than a word. Return shifted out part
static int modshr(unsigned int n,spint *a) {
	int i;
	spint r=a[0]&(((spint)1<<n)-(spint)1);
	for (i=0;i<7;i++) {
		a[i]=(a[i]>>n) + ((a[i+1]<<(61u-n))&(spint)0x1fffffffffffffff);
	}
	a[7]=a[7]>>n;
	return r;
}

//divide by 2. Shift right 1 bit (or add p and shift right one bit)
static void modhaf(spint *n) {
	int lsb;
	spint t[8];
	(void)prop(n);
	modcpy(n,t);
	lsb=modshr(1,t);
	n[0]-=(spint)1;
	n[2]+=((spint)0x12f82d0000000000u);
	n[3]+=((spint)0x15d42d2e97233d29u);
	n[4]+=((spint)0x43dadd9997fbe0du);
	n[5]+=((spint)0xe05f9ddcd482c43u);
	n[6]+=((spint)0x154bdefa808a1ac6u);
	n[7]+=((spint)0xb11dd235847deu);
	(void)prop(n);
	modshr(1,n);
	modcmv(1-lsb,t,n);
}

//set a= 2^r
static void mod2r(unsigned int r,spint *a) {
	unsigned int n=r/61u;
	unsigned int m=r%61u;
	modzer(a);
	if (r>=60*8) return;
	a[n]=1; a[n]<<=m;
nres(a,a);
}

//export to byte array
static void modexp(const spint *a,char *b) {
	int i;
	spint c[8];
	redc(a,c);
	for (i=59;i>=0;i--) {
		b[i]=c[0]&(spint)0xff;
		(void)modshr(8,c);
	}
}

//import from byte array
//returns 1 if in range, else 0
static int modimp(const char *b, spint *a) {
	int i,res;
	for (i=0;i<8;i++) {
		a[i]=0;
	}
	for (i=0;i<60;i++) {
		modshl(8,a);
		a[0]+=(spint)(unsigned char)b[i];
	}
	res=(int)modfsb(a);
	nres(a,a);
	return res;
}

//determine sign
static int modsign(const spint *a) {
	spint c[8];
	redc(a,c);
	return c[0]%2;
}

//return true if equal
static int modcmp(const spint *a,const spint *b) {
	spint c[8],d[8];
	int i,eq=1;
	redc(a,c);
	redc(b,d);
	for (i=0;i<8;i++) {
		eq&=(((c[i]^d[i])-1)>>61)&1;
	}
	return eq;
}

