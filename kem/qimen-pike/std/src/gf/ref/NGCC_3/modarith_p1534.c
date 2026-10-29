
//Automatically generated modular arithmetic C code
//Command line : python monty.py 64 0x22606deb050ed1445554f51ce0e783f6a886397f71da19e514541bc051219e91bdfbff3ede30e07607a2821a8511c268f4c3a493432f085476f58123de8fab63ef81c420b2dfbb3fb3e2fa38f5419baf8cd6ed92b85bd0cb3a5035c534b5f3afdae93fda6645a281e3cd1244524530814e9c3615eab1df2a74f745f71f7b456bffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
//Python Script by Mike Scott (Technology Innovation Institute, UAE, 2025)

#include <stdio.h>
#include <stdint.h>

#define sspint int64_t
#define spint uint64_t
#define dpint __uint128_t
#define sdpint __int128_t
#define Wordlength 64
#define Nlimbs 26
#define Radix 60
#define Nbits 1534
#define Nbytes 192

#define MONTGOMERY
//propagate carries
static spint inline prop(spint *n) {
	int i;
	spint mask=((spint)1<<60u)-(spint)1;
	sspint carry=(sspint)n[0];
	carry>>=60u;
	n[0]&=mask;
	for (i=1;i<25;i++) {
		carry+=(sspint)n[i];
		n[i] = (spint)carry & mask;
		carry>>=60u;
	}
	n[25]+=(spint)carry;
	return -((n[25]>>1)>>62u);
}

//propagate carries and add p if negative, propagate carries again
static spint flatten(spint *n) {
	spint carry=prop(n);
	n[0]-=(spint)1u&carry;
	n[8]+=((spint)0xf7b456c00000000u)&carry;
	n[9]+=((spint)0xb1df2a74f745f71u)&carry;
	n[10]+=((spint)0x530814e9c3615eau)&carry;
	n[11]+=((spint)0xa281e3cd1244524u)&carry;
	n[12]+=((spint)0x3afdae93fda6645u)&carry;
	n[13]+=((spint)0xcb3a5035c534b5fu)&carry;
	n[14]+=((spint)0xf8cd6ed92b85bd0u)&carry;
	n[15]+=((spint)0xb3e2fa38f5419bau)&carry;
	n[16]+=((spint)0xf81c420b2dfbb3fu)&carry;
	n[17]+=((spint)0xf58123de8fab63eu)&carry;
	n[18]+=((spint)0x3a493432f085476u)&carry;
	n[19]+=((spint)0x821a8511c268f4cu)&carry;
	n[20]+=((spint)0xf3ede30e07607a2u)&carry;
	n[21]+=((spint)0xc051219e91bdfbfu)&carry;
	n[22]+=((spint)0xf71da19e514541bu)&carry;
	n[23]+=((spint)0xe0e783f6a886397u)&carry;
	n[24]+=((spint)0x50ed1445554f51cu)&carry;
	n[25]+=((spint)0x22606deb0u)&carry;
	(void)prop(n);
	return (carry&1);
}

//Montgomery final subtract
static spint modfsb(spint *n) {
	n[0]+=(spint)1u;
	n[8]-=(spint)0xf7b456c00000000u;
	n[9]-=(spint)0xb1df2a74f745f71u;
	n[10]-=(spint)0x530814e9c3615eau;
	n[11]-=(spint)0xa281e3cd1244524u;
	n[12]-=(spint)0x3afdae93fda6645u;
	n[13]-=(spint)0xcb3a5035c534b5fu;
	n[14]-=(spint)0xf8cd6ed92b85bd0u;
	n[15]-=(spint)0xb3e2fa38f5419bau;
	n[16]-=(spint)0xf81c420b2dfbb3fu;
	n[17]-=(spint)0xf58123de8fab63eu;
	n[18]-=(spint)0x3a493432f085476u;
	n[19]-=(spint)0x821a8511c268f4cu;
	n[20]-=(spint)0xf3ede30e07607a2u;
	n[21]-=(spint)0xc051219e91bdfbfu;
	n[22]-=(spint)0xf71da19e514541bu;
	n[23]-=(spint)0xe0e783f6a886397u;
	n[24]-=(spint)0x50ed1445554f51cu;
	n[25]-=(spint)0x22606deb0u;
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
	n[13]=a[13]+b[13];
	n[14]=a[14]+b[14];
	n[15]=a[15]+b[15];
	n[16]=a[16]+b[16];
	n[17]=a[17]+b[17];
	n[18]=a[18]+b[18];
	n[19]=a[19]+b[19];
	n[20]=a[20]+b[20];
	n[21]=a[21]+b[21];
	n[22]=a[22]+b[22];
	n[23]=a[23]+b[23];
	n[24]=a[24]+b[24];
	n[25]=a[25]+b[25];
	n[0]+=(spint)2u;
	n[8]-=(spint)0x1ef68ad800000000u;
	n[9]-=(spint)0x163be54e9ee8bee2u;
	n[10]-=(spint)0xa61029d386c2bd4u;
	n[11]-=(spint)0x14503c79a2488a48u;
	n[12]-=(spint)0x75fb5d27fb4cc8au;
	n[13]-=(spint)0x19674a06b8a696beu;
	n[14]-=(spint)0x1f19addb2570b7a0u;
	n[15]-=(spint)0x167c5f471ea83374u;
	n[16]-=(spint)0x1f03884165bf767eu;
	n[17]-=(spint)0x1eb0247bd1f56c7cu;
	n[18]-=(spint)0x74926865e10a8ecu;
	n[19]-=(spint)0x104350a2384d1e98u;
	n[20]-=(spint)0x1e7dbc61c0ec0f44u;
	n[21]-=(spint)0x180a2433d237bf7eu;
	n[22]-=(spint)0x1ee3b433ca28a836u;
	n[23]-=(spint)0x1c1cf07ed510c72eu;
	n[24]-=(spint)0xa1da288aaa9ea38u;
	n[25]-=(spint)0x44c0dbd60u;
	carry=prop(n);
	n[0]-=(spint)2u&carry;
	n[8]+=((spint)0x1ef68ad800000000u)&carry;
	n[9]+=((spint)0x163be54e9ee8bee2u)&carry;
	n[10]+=((spint)0xa61029d386c2bd4u)&carry;
	n[11]+=((spint)0x14503c79a2488a48u)&carry;
	n[12]+=((spint)0x75fb5d27fb4cc8au)&carry;
	n[13]+=((spint)0x19674a06b8a696beu)&carry;
	n[14]+=((spint)0x1f19addb2570b7a0u)&carry;
	n[15]+=((spint)0x167c5f471ea83374u)&carry;
	n[16]+=((spint)0x1f03884165bf767eu)&carry;
	n[17]+=((spint)0x1eb0247bd1f56c7cu)&carry;
	n[18]+=((spint)0x74926865e10a8ecu)&carry;
	n[19]+=((spint)0x104350a2384d1e98u)&carry;
	n[20]+=((spint)0x1e7dbc61c0ec0f44u)&carry;
	n[21]+=((spint)0x180a2433d237bf7eu)&carry;
	n[22]+=((spint)0x1ee3b433ca28a836u)&carry;
	n[23]+=((spint)0x1c1cf07ed510c72eu)&carry;
	n[24]+=((spint)0xa1da288aaa9ea38u)&carry;
	n[25]+=((spint)0x44c0dbd60u)&carry;
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
	n[13]=a[13]-b[13];
	n[14]=a[14]-b[14];
	n[15]=a[15]-b[15];
	n[16]=a[16]-b[16];
	n[17]=a[17]-b[17];
	n[18]=a[18]-b[18];
	n[19]=a[19]-b[19];
	n[20]=a[20]-b[20];
	n[21]=a[21]-b[21];
	n[22]=a[22]-b[22];
	n[23]=a[23]-b[23];
	n[24]=a[24]-b[24];
	n[25]=a[25]-b[25];
	carry=prop(n);
	n[0]-=(spint)2u&carry;
	n[8]+=((spint)0x1ef68ad800000000u)&carry;
	n[9]+=((spint)0x163be54e9ee8bee2u)&carry;
	n[10]+=((spint)0xa61029d386c2bd4u)&carry;
	n[11]+=((spint)0x14503c79a2488a48u)&carry;
	n[12]+=((spint)0x75fb5d27fb4cc8au)&carry;
	n[13]+=((spint)0x19674a06b8a696beu)&carry;
	n[14]+=((spint)0x1f19addb2570b7a0u)&carry;
	n[15]+=((spint)0x167c5f471ea83374u)&carry;
	n[16]+=((spint)0x1f03884165bf767eu)&carry;
	n[17]+=((spint)0x1eb0247bd1f56c7cu)&carry;
	n[18]+=((spint)0x74926865e10a8ecu)&carry;
	n[19]+=((spint)0x104350a2384d1e98u)&carry;
	n[20]+=((spint)0x1e7dbc61c0ec0f44u)&carry;
	n[21]+=((spint)0x180a2433d237bf7eu)&carry;
	n[22]+=((spint)0x1ee3b433ca28a836u)&carry;
	n[23]+=((spint)0x1c1cf07ed510c72eu)&carry;
	n[24]+=((spint)0xa1da288aaa9ea38u)&carry;
	n[25]+=((spint)0x44c0dbd60u)&carry;
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
	n[13]=(spint)0-b[13];
	n[14]=(spint)0-b[14];
	n[15]=(spint)0-b[15];
	n[16]=(spint)0-b[16];
	n[17]=(spint)0-b[17];
	n[18]=(spint)0-b[18];
	n[19]=(spint)0-b[19];
	n[20]=(spint)0-b[20];
	n[21]=(spint)0-b[21];
	n[22]=(spint)0-b[22];
	n[23]=(spint)0-b[23];
	n[24]=(spint)0-b[24];
	n[25]=(spint)0-b[25];
	carry=prop(n);
	n[0]-=(spint)2u&carry;
	n[8]+=((spint)0x1ef68ad800000000u)&carry;
	n[9]+=((spint)0x163be54e9ee8bee2u)&carry;
	n[10]+=((spint)0xa61029d386c2bd4u)&carry;
	n[11]+=((spint)0x14503c79a2488a48u)&carry;
	n[12]+=((spint)0x75fb5d27fb4cc8au)&carry;
	n[13]+=((spint)0x19674a06b8a696beu)&carry;
	n[14]+=((spint)0x1f19addb2570b7a0u)&carry;
	n[15]+=((spint)0x167c5f471ea83374u)&carry;
	n[16]+=((spint)0x1f03884165bf767eu)&carry;
	n[17]+=((spint)0x1eb0247bd1f56c7cu)&carry;
	n[18]+=((spint)0x74926865e10a8ecu)&carry;
	n[19]+=((spint)0x104350a2384d1e98u)&carry;
	n[20]+=((spint)0x1e7dbc61c0ec0f44u)&carry;
	n[21]+=((spint)0x180a2433d237bf7eu)&carry;
	n[22]+=((spint)0x1ee3b433ca28a836u)&carry;
	n[23]+=((spint)0x1c1cf07ed510c72eu)&carry;
	n[24]+=((spint)0xa1da288aaa9ea38u)&carry;
	n[25]+=((spint)0x44c0dbd60u)&carry;
	(void)prop(n);
}

// Overflow limit   = 340282366920938463463374607431768211456
// maximum possible = 50309305117991998587621721816881649231
// Modular multiplication, c=a*b mod 2p
static void modmul(const spint *a,const spint *b,spint *c) {
	dpint t=0;
	spint p8=0xf7b456c00000000u;
	spint p9=0xb1df2a74f745f71u;
	spint p10=0x530814e9c3615eau;
	spint p11=0xa281e3cd1244524u;
	spint p12=0x3afdae93fda6645u;
	spint p13=0xcb3a5035c534b5fu;
	spint p14=0xf8cd6ed92b85bd0u;
	spint p15=0xb3e2fa38f5419bau;
	spint p16=0xf81c420b2dfbb3fu;
	spint p17=0xf58123de8fab63eu;
	spint p18=0x3a493432f085476u;
	spint p19=0x821a8511c268f4cu;
	spint p20=0xf3ede30e07607a2u;
	spint p21=0xc051219e91bdfbfu;
	spint p22=0xf71da19e514541bu;
	spint p23=0xe0e783f6a886397u;
	spint p24=0x50ed1445554f51cu;
	spint p25=0x22606deb0u;
	spint q=((spint)1<<60u); // q is unsaturated radix 
	spint mask=(spint)(q-(spint)1);
	t+=(dpint)a[0]*b[0]; spint v0=((spint)t & mask); t>>=60;
	t+=(dpint)a[0]*b[1]; t+=(dpint)a[1]*b[0]; spint v1=((spint)t & mask);  t>>=60;
	t+=(dpint)a[0]*b[2]; t+=(dpint)a[1]*b[1]; t+=(dpint)a[2]*b[0]; spint v2=((spint)t & mask);  t>>=60;
	t+=(dpint)a[0]*b[3]; t+=(dpint)a[1]*b[2]; t+=(dpint)a[2]*b[1]; t+=(dpint)a[3]*b[0]; spint v3=((spint)t & mask);  t>>=60;
	t+=(dpint)a[0]*b[4]; t+=(dpint)a[1]*b[3]; t+=(dpint)a[2]*b[2]; t+=(dpint)a[3]*b[1]; t+=(dpint)a[4]*b[0]; spint v4=((spint)t & mask);  t>>=60;
	t+=(dpint)a[0]*b[5]; t+=(dpint)a[1]*b[4]; t+=(dpint)a[2]*b[3]; t+=(dpint)a[3]*b[2]; t+=(dpint)a[4]*b[1]; t+=(dpint)a[5]*b[0]; spint v5=((spint)t & mask);  t>>=60;
	t+=(dpint)a[0]*b[6]; t+=(dpint)a[1]*b[5]; t+=(dpint)a[2]*b[4]; t+=(dpint)a[3]*b[3]; t+=(dpint)a[4]*b[2]; t+=(dpint)a[5]*b[1]; t+=(dpint)a[6]*b[0]; spint v6=((spint)t & mask);  t>>=60;
	t+=(dpint)a[0]*b[7]; t+=(dpint)a[1]*b[6]; t+=(dpint)a[2]*b[5]; t+=(dpint)a[3]*b[4]; t+=(dpint)a[4]*b[3]; t+=(dpint)a[5]*b[2]; t+=(dpint)a[6]*b[1]; t+=(dpint)a[7]*b[0]; spint v7=((spint)t & mask);  t>>=60;
	t+=(dpint)a[0]*b[8]; t+=(dpint)a[1]*b[7]; t+=(dpint)a[2]*b[6]; t+=(dpint)a[3]*b[5]; t+=(dpint)a[4]*b[4]; t+=(dpint)a[5]*b[3]; t+=(dpint)a[6]*b[2]; t+=(dpint)a[7]*b[1]; t+=(dpint)a[8]*b[0]; t+=(dpint)v0*(dpint)p8;  spint v8=((spint)t & mask);  t>>=60;
	t+=(dpint)a[0]*b[9]; t+=(dpint)a[1]*b[8]; t+=(dpint)a[2]*b[7]; t+=(dpint)a[3]*b[6]; t+=(dpint)a[4]*b[5]; t+=(dpint)a[5]*b[4]; t+=(dpint)a[6]*b[3]; t+=(dpint)a[7]*b[2]; t+=(dpint)a[8]*b[1]; t+=(dpint)a[9]*b[0]; t+=(dpint)v0*(dpint)p9;  t+=(dpint)v1*(dpint)p8;  spint v9=((spint)t & mask);  t>>=60;
	t+=(dpint)a[0]*b[10]; t+=(dpint)a[1]*b[9]; t+=(dpint)a[2]*b[8]; t+=(dpint)a[3]*b[7]; t+=(dpint)a[4]*b[6]; t+=(dpint)a[5]*b[5]; t+=(dpint)a[6]*b[4]; t+=(dpint)a[7]*b[3]; t+=(dpint)a[8]*b[2]; t+=(dpint)a[9]*b[1]; t+=(dpint)a[10]*b[0]; t+=(dpint)v0*(dpint)p10;  t+=(dpint)v1*(dpint)p9;  t+=(dpint)v2*(dpint)p8;  spint v10=((spint)t & mask);  t>>=60;
	t+=(dpint)a[0]*b[11]; t+=(dpint)a[1]*b[10]; t+=(dpint)a[2]*b[9]; t+=(dpint)a[3]*b[8]; t+=(dpint)a[4]*b[7]; t+=(dpint)a[5]*b[6]; t+=(dpint)a[6]*b[5]; t+=(dpint)a[7]*b[4]; t+=(dpint)a[8]*b[3]; t+=(dpint)a[9]*b[2]; t+=(dpint)a[10]*b[1]; t+=(dpint)a[11]*b[0]; t+=(dpint)v0*(dpint)p11;  t+=(dpint)v1*(dpint)p10;  t+=(dpint)v2*(dpint)p9;  t+=(dpint)v3*(dpint)p8;  spint v11=((spint)t & mask);  t>>=60;
	t+=(dpint)a[0]*b[12]; t+=(dpint)a[1]*b[11]; t+=(dpint)a[2]*b[10]; t+=(dpint)a[3]*b[9]; t+=(dpint)a[4]*b[8]; t+=(dpint)a[5]*b[7]; t+=(dpint)a[6]*b[6]; t+=(dpint)a[7]*b[5]; t+=(dpint)a[8]*b[4]; t+=(dpint)a[9]*b[3]; t+=(dpint)a[10]*b[2]; t+=(dpint)a[11]*b[1]; t+=(dpint)a[12]*b[0]; t+=(dpint)v0*(dpint)p12;  t+=(dpint)v1*(dpint)p11;  t+=(dpint)v2*(dpint)p10;  t+=(dpint)v3*(dpint)p9;  t+=(dpint)v4*(dpint)p8;  spint v12=((spint)t & mask);  t>>=60;
	t+=(dpint)a[0]*b[13]; t+=(dpint)a[1]*b[12]; t+=(dpint)a[2]*b[11]; t+=(dpint)a[3]*b[10]; t+=(dpint)a[4]*b[9]; t+=(dpint)a[5]*b[8]; t+=(dpint)a[6]*b[7]; t+=(dpint)a[7]*b[6]; t+=(dpint)a[8]*b[5]; t+=(dpint)a[9]*b[4]; t+=(dpint)a[10]*b[3]; t+=(dpint)a[11]*b[2]; t+=(dpint)a[12]*b[1]; t+=(dpint)a[13]*b[0]; t+=(dpint)v0*(dpint)p13;  t+=(dpint)v1*(dpint)p12;  t+=(dpint)v2*(dpint)p11;  t+=(dpint)v3*(dpint)p10;  t+=(dpint)v4*(dpint)p9;  t+=(dpint)v5*(dpint)p8;  spint v13=((spint)t & mask);  t>>=60;
	t+=(dpint)a[0]*b[14]; t+=(dpint)a[1]*b[13]; t+=(dpint)a[2]*b[12]; t+=(dpint)a[3]*b[11]; t+=(dpint)a[4]*b[10]; t+=(dpint)a[5]*b[9]; t+=(dpint)a[6]*b[8]; t+=(dpint)a[7]*b[7]; t+=(dpint)a[8]*b[6]; t+=(dpint)a[9]*b[5]; t+=(dpint)a[10]*b[4]; t+=(dpint)a[11]*b[3]; t+=(dpint)a[12]*b[2]; t+=(dpint)a[13]*b[1]; t+=(dpint)a[14]*b[0]; t+=(dpint)v0*(dpint)p14;  t+=(dpint)v1*(dpint)p13;  t+=(dpint)v2*(dpint)p12;  t+=(dpint)v3*(dpint)p11;  t+=(dpint)v4*(dpint)p10;  t+=(dpint)v5*(dpint)p9;  t+=(dpint)v6*(dpint)p8;  spint v14=((spint)t & mask);  t>>=60;
	t+=(dpint)a[0]*b[15]; t+=(dpint)a[1]*b[14]; t+=(dpint)a[2]*b[13]; t+=(dpint)a[3]*b[12]; t+=(dpint)a[4]*b[11]; t+=(dpint)a[5]*b[10]; t+=(dpint)a[6]*b[9]; t+=(dpint)a[7]*b[8]; t+=(dpint)a[8]*b[7]; t+=(dpint)a[9]*b[6]; t+=(dpint)a[10]*b[5]; t+=(dpint)a[11]*b[4]; t+=(dpint)a[12]*b[3]; t+=(dpint)a[13]*b[2]; t+=(dpint)a[14]*b[1]; t+=(dpint)a[15]*b[0]; t+=(dpint)v0*(dpint)p15;  t+=(dpint)v1*(dpint)p14;  t+=(dpint)v2*(dpint)p13;  t+=(dpint)v3*(dpint)p12;  t+=(dpint)v4*(dpint)p11;  t+=(dpint)v5*(dpint)p10;  t+=(dpint)v6*(dpint)p9;  t+=(dpint)v7*(dpint)p8;  spint v15=((spint)t & mask);  t>>=60;
	t+=(dpint)a[0]*b[16]; t+=(dpint)a[1]*b[15]; t+=(dpint)a[2]*b[14]; t+=(dpint)a[3]*b[13]; t+=(dpint)a[4]*b[12]; t+=(dpint)a[5]*b[11]; t+=(dpint)a[6]*b[10]; t+=(dpint)a[7]*b[9]; t+=(dpint)a[8]*b[8]; t+=(dpint)a[9]*b[7]; t+=(dpint)a[10]*b[6]; t+=(dpint)a[11]*b[5]; t+=(dpint)a[12]*b[4]; t+=(dpint)a[13]*b[3]; t+=(dpint)a[14]*b[2]; t+=(dpint)a[15]*b[1]; t+=(dpint)a[16]*b[0]; t+=(dpint)v0*(dpint)p16;  t+=(dpint)v1*(dpint)p15;  t+=(dpint)v2*(dpint)p14;  t+=(dpint)v3*(dpint)p13;  t+=(dpint)v4*(dpint)p12;  t+=(dpint)v5*(dpint)p11;  t+=(dpint)v6*(dpint)p10;  t+=(dpint)v7*(dpint)p9;  t+=(dpint)v8*(dpint)p8;  spint v16=((spint)t & mask);  t>>=60;
	t+=(dpint)a[0]*b[17]; t+=(dpint)a[1]*b[16]; t+=(dpint)a[2]*b[15]; t+=(dpint)a[3]*b[14]; t+=(dpint)a[4]*b[13]; t+=(dpint)a[5]*b[12]; t+=(dpint)a[6]*b[11]; t+=(dpint)a[7]*b[10]; t+=(dpint)a[8]*b[9]; t+=(dpint)a[9]*b[8]; t+=(dpint)a[10]*b[7]; t+=(dpint)a[11]*b[6]; t+=(dpint)a[12]*b[5]; t+=(dpint)a[13]*b[4]; t+=(dpint)a[14]*b[3]; t+=(dpint)a[15]*b[2]; t+=(dpint)a[16]*b[1]; t+=(dpint)a[17]*b[0]; t+=(dpint)v0*(dpint)p17;  t+=(dpint)v1*(dpint)p16;  t+=(dpint)v2*(dpint)p15;  t+=(dpint)v3*(dpint)p14;  t+=(dpint)v4*(dpint)p13;  t+=(dpint)v5*(dpint)p12;  t+=(dpint)v6*(dpint)p11;  t+=(dpint)v7*(dpint)p10;  t+=(dpint)v8*(dpint)p9;  t+=(dpint)v9*(dpint)p8;  spint v17=((spint)t & mask);  t>>=60;
	t+=(dpint)a[0]*b[18]; t+=(dpint)a[1]*b[17]; t+=(dpint)a[2]*b[16]; t+=(dpint)a[3]*b[15]; t+=(dpint)a[4]*b[14]; t+=(dpint)a[5]*b[13]; t+=(dpint)a[6]*b[12]; t+=(dpint)a[7]*b[11]; t+=(dpint)a[8]*b[10]; t+=(dpint)a[9]*b[9]; t+=(dpint)a[10]*b[8]; t+=(dpint)a[11]*b[7]; t+=(dpint)a[12]*b[6]; t+=(dpint)a[13]*b[5]; t+=(dpint)a[14]*b[4]; t+=(dpint)a[15]*b[3]; t+=(dpint)a[16]*b[2]; t+=(dpint)a[17]*b[1]; t+=(dpint)a[18]*b[0]; t+=(dpint)v0*(dpint)p18;  t+=(dpint)v1*(dpint)p17;  t+=(dpint)v2*(dpint)p16;  t+=(dpint)v3*(dpint)p15;  t+=(dpint)v4*(dpint)p14;  t+=(dpint)v5*(dpint)p13;  t+=(dpint)v6*(dpint)p12;  t+=(dpint)v7*(dpint)p11;  t+=(dpint)v8*(dpint)p10;  t+=(dpint)v9*(dpint)p9;  t+=(dpint)v10*(dpint)p8;  spint v18=((spint)t & mask);  t>>=60;
	t+=(dpint)a[0]*b[19]; t+=(dpint)a[1]*b[18]; t+=(dpint)a[2]*b[17]; t+=(dpint)a[3]*b[16]; t+=(dpint)a[4]*b[15]; t+=(dpint)a[5]*b[14]; t+=(dpint)a[6]*b[13]; t+=(dpint)a[7]*b[12]; t+=(dpint)a[8]*b[11]; t+=(dpint)a[9]*b[10]; t+=(dpint)a[10]*b[9]; t+=(dpint)a[11]*b[8]; t+=(dpint)a[12]*b[7]; t+=(dpint)a[13]*b[6]; t+=(dpint)a[14]*b[5]; t+=(dpint)a[15]*b[4]; t+=(dpint)a[16]*b[3]; t+=(dpint)a[17]*b[2]; t+=(dpint)a[18]*b[1]; t+=(dpint)a[19]*b[0]; t+=(dpint)v0*(dpint)p19;  t+=(dpint)v1*(dpint)p18;  t+=(dpint)v2*(dpint)p17;  t+=(dpint)v3*(dpint)p16;  t+=(dpint)v4*(dpint)p15;  t+=(dpint)v5*(dpint)p14;  t+=(dpint)v6*(dpint)p13;  t+=(dpint)v7*(dpint)p12;  t+=(dpint)v8*(dpint)p11;  t+=(dpint)v9*(dpint)p10;  t+=(dpint)v10*(dpint)p9;  t+=(dpint)v11*(dpint)p8;  spint v19=((spint)t & mask);  t>>=60;
	t+=(dpint)a[0]*b[20]; t+=(dpint)a[1]*b[19]; t+=(dpint)a[2]*b[18]; t+=(dpint)a[3]*b[17]; t+=(dpint)a[4]*b[16]; t+=(dpint)a[5]*b[15]; t+=(dpint)a[6]*b[14]; t+=(dpint)a[7]*b[13]; t+=(dpint)a[8]*b[12]; t+=(dpint)a[9]*b[11]; t+=(dpint)a[10]*b[10]; t+=(dpint)a[11]*b[9]; t+=(dpint)a[12]*b[8]; t+=(dpint)a[13]*b[7]; t+=(dpint)a[14]*b[6]; t+=(dpint)a[15]*b[5]; t+=(dpint)a[16]*b[4]; t+=(dpint)a[17]*b[3]; t+=(dpint)a[18]*b[2]; t+=(dpint)a[19]*b[1]; t+=(dpint)a[20]*b[0]; t+=(dpint)v0*(dpint)p20;  t+=(dpint)v1*(dpint)p19;  t+=(dpint)v2*(dpint)p18;  t+=(dpint)v3*(dpint)p17;  t+=(dpint)v4*(dpint)p16;  t+=(dpint)v5*(dpint)p15;  t+=(dpint)v6*(dpint)p14;  t+=(dpint)v7*(dpint)p13;  t+=(dpint)v8*(dpint)p12;  t+=(dpint)v9*(dpint)p11;  t+=(dpint)v10*(dpint)p10;  t+=(dpint)v11*(dpint)p9;  t+=(dpint)v12*(dpint)p8;  spint v20=((spint)t & mask);  t>>=60;
	t+=(dpint)a[0]*b[21]; t+=(dpint)a[1]*b[20]; t+=(dpint)a[2]*b[19]; t+=(dpint)a[3]*b[18]; t+=(dpint)a[4]*b[17]; t+=(dpint)a[5]*b[16]; t+=(dpint)a[6]*b[15]; t+=(dpint)a[7]*b[14]; t+=(dpint)a[8]*b[13]; t+=(dpint)a[9]*b[12]; t+=(dpint)a[10]*b[11]; t+=(dpint)a[11]*b[10]; t+=(dpint)a[12]*b[9]; t+=(dpint)a[13]*b[8]; t+=(dpint)a[14]*b[7]; t+=(dpint)a[15]*b[6]; t+=(dpint)a[16]*b[5]; t+=(dpint)a[17]*b[4]; t+=(dpint)a[18]*b[3]; t+=(dpint)a[19]*b[2]; t+=(dpint)a[20]*b[1]; t+=(dpint)a[21]*b[0]; t+=(dpint)v0*(dpint)p21;  t+=(dpint)v1*(dpint)p20;  t+=(dpint)v2*(dpint)p19;  t+=(dpint)v3*(dpint)p18;  t+=(dpint)v4*(dpint)p17;  t+=(dpint)v5*(dpint)p16;  t+=(dpint)v6*(dpint)p15;  t+=(dpint)v7*(dpint)p14;  t+=(dpint)v8*(dpint)p13;  t+=(dpint)v9*(dpint)p12;  t+=(dpint)v10*(dpint)p11;  t+=(dpint)v11*(dpint)p10;  t+=(dpint)v12*(dpint)p9;  t+=(dpint)v13*(dpint)p8;  spint v21=((spint)t & mask);  t>>=60;
	t+=(dpint)a[0]*b[22]; t+=(dpint)a[1]*b[21]; t+=(dpint)a[2]*b[20]; t+=(dpint)a[3]*b[19]; t+=(dpint)a[4]*b[18]; t+=(dpint)a[5]*b[17]; t+=(dpint)a[6]*b[16]; t+=(dpint)a[7]*b[15]; t+=(dpint)a[8]*b[14]; t+=(dpint)a[9]*b[13]; t+=(dpint)a[10]*b[12]; t+=(dpint)a[11]*b[11]; t+=(dpint)a[12]*b[10]; t+=(dpint)a[13]*b[9]; t+=(dpint)a[14]*b[8]; t+=(dpint)a[15]*b[7]; t+=(dpint)a[16]*b[6]; t+=(dpint)a[17]*b[5]; t+=(dpint)a[18]*b[4]; t+=(dpint)a[19]*b[3]; t+=(dpint)a[20]*b[2]; t+=(dpint)a[21]*b[1]; t+=(dpint)a[22]*b[0]; t+=(dpint)v0*(dpint)p22;  t+=(dpint)v1*(dpint)p21;  t+=(dpint)v2*(dpint)p20;  t+=(dpint)v3*(dpint)p19;  t+=(dpint)v4*(dpint)p18;  t+=(dpint)v5*(dpint)p17;  t+=(dpint)v6*(dpint)p16;  t+=(dpint)v7*(dpint)p15;  t+=(dpint)v8*(dpint)p14;  t+=(dpint)v9*(dpint)p13;  t+=(dpint)v10*(dpint)p12;  t+=(dpint)v11*(dpint)p11;  t+=(dpint)v12*(dpint)p10;  t+=(dpint)v13*(dpint)p9;  t+=(dpint)v14*(dpint)p8;  spint v22=((spint)t & mask);  t>>=60;
	t+=(dpint)a[0]*b[23]; t+=(dpint)a[1]*b[22]; t+=(dpint)a[2]*b[21]; t+=(dpint)a[3]*b[20]; t+=(dpint)a[4]*b[19]; t+=(dpint)a[5]*b[18]; t+=(dpint)a[6]*b[17]; t+=(dpint)a[7]*b[16]; t+=(dpint)a[8]*b[15]; t+=(dpint)a[9]*b[14]; t+=(dpint)a[10]*b[13]; t+=(dpint)a[11]*b[12]; t+=(dpint)a[12]*b[11]; t+=(dpint)a[13]*b[10]; t+=(dpint)a[14]*b[9]; t+=(dpint)a[15]*b[8]; t+=(dpint)a[16]*b[7]; t+=(dpint)a[17]*b[6]; t+=(dpint)a[18]*b[5]; t+=(dpint)a[19]*b[4]; t+=(dpint)a[20]*b[3]; t+=(dpint)a[21]*b[2]; t+=(dpint)a[22]*b[1]; t+=(dpint)a[23]*b[0]; t+=(dpint)v0*(dpint)p23;  t+=(dpint)v1*(dpint)p22;  t+=(dpint)v2*(dpint)p21;  t+=(dpint)v3*(dpint)p20;  t+=(dpint)v4*(dpint)p19;  t+=(dpint)v5*(dpint)p18;  t+=(dpint)v6*(dpint)p17;  t+=(dpint)v7*(dpint)p16;  t+=(dpint)v8*(dpint)p15;  t+=(dpint)v9*(dpint)p14;  t+=(dpint)v10*(dpint)p13;  t+=(dpint)v11*(dpint)p12;  t+=(dpint)v12*(dpint)p11;  t+=(dpint)v13*(dpint)p10;  t+=(dpint)v14*(dpint)p9;  t+=(dpint)v15*(dpint)p8;  spint v23=((spint)t & mask);  t>>=60;
	t+=(dpint)a[0]*b[24]; t+=(dpint)a[1]*b[23]; t+=(dpint)a[2]*b[22]; t+=(dpint)a[3]*b[21]; t+=(dpint)a[4]*b[20]; t+=(dpint)a[5]*b[19]; t+=(dpint)a[6]*b[18]; t+=(dpint)a[7]*b[17]; t+=(dpint)a[8]*b[16]; t+=(dpint)a[9]*b[15]; t+=(dpint)a[10]*b[14]; t+=(dpint)a[11]*b[13]; t+=(dpint)a[12]*b[12]; t+=(dpint)a[13]*b[11]; t+=(dpint)a[14]*b[10]; t+=(dpint)a[15]*b[9]; t+=(dpint)a[16]*b[8]; t+=(dpint)a[17]*b[7]; t+=(dpint)a[18]*b[6]; t+=(dpint)a[19]*b[5]; t+=(dpint)a[20]*b[4]; t+=(dpint)a[21]*b[3]; t+=(dpint)a[22]*b[2]; t+=(dpint)a[23]*b[1]; t+=(dpint)a[24]*b[0]; t+=(dpint)v0*(dpint)p24;  t+=(dpint)v1*(dpint)p23;  t+=(dpint)v2*(dpint)p22;  t+=(dpint)v3*(dpint)p21;  t+=(dpint)v4*(dpint)p20;  t+=(dpint)v5*(dpint)p19;  t+=(dpint)v6*(dpint)p18;  t+=(dpint)v7*(dpint)p17;  t+=(dpint)v8*(dpint)p16;  t+=(dpint)v9*(dpint)p15;  t+=(dpint)v10*(dpint)p14;  t+=(dpint)v11*(dpint)p13;  t+=(dpint)v12*(dpint)p12;  t+=(dpint)v13*(dpint)p11;  t+=(dpint)v14*(dpint)p10;  t+=(dpint)v15*(dpint)p9;  t+=(dpint)v16*(dpint)p8;  spint v24=((spint)t & mask);  t>>=60;
	t+=(dpint)a[0]*b[25]; t+=(dpint)a[1]*b[24]; t+=(dpint)a[2]*b[23]; t+=(dpint)a[3]*b[22]; t+=(dpint)a[4]*b[21]; t+=(dpint)a[5]*b[20]; t+=(dpint)a[6]*b[19]; t+=(dpint)a[7]*b[18]; t+=(dpint)a[8]*b[17]; t+=(dpint)a[9]*b[16]; t+=(dpint)a[10]*b[15]; t+=(dpint)a[11]*b[14]; t+=(dpint)a[12]*b[13]; t+=(dpint)a[13]*b[12]; t+=(dpint)a[14]*b[11]; t+=(dpint)a[15]*b[10]; t+=(dpint)a[16]*b[9]; t+=(dpint)a[17]*b[8]; t+=(dpint)a[18]*b[7]; t+=(dpint)a[19]*b[6]; t+=(dpint)a[20]*b[5]; t+=(dpint)a[21]*b[4]; t+=(dpint)a[22]*b[3]; t+=(dpint)a[23]*b[2]; t+=(dpint)a[24]*b[1]; t+=(dpint)a[25]*b[0]; t+=(dpint)v0*(dpint)p25;  t+=(dpint)v1*(dpint)p24;  t+=(dpint)v2*(dpint)p23;  t+=(dpint)v3*(dpint)p22;  t+=(dpint)v4*(dpint)p21;  t+=(dpint)v5*(dpint)p20;  t+=(dpint)v6*(dpint)p19;  t+=(dpint)v7*(dpint)p18;  t+=(dpint)v8*(dpint)p17;  t+=(dpint)v9*(dpint)p16;  t+=(dpint)v10*(dpint)p15;  t+=(dpint)v11*(dpint)p14;  t+=(dpint)v12*(dpint)p13;  t+=(dpint)v13*(dpint)p12;  t+=(dpint)v14*(dpint)p11;  t+=(dpint)v15*(dpint)p10;  t+=(dpint)v16*(dpint)p9;  t+=(dpint)v17*(dpint)p8;  spint v25=((spint)t & mask);  t>>=60;
	t+=(dpint)a[1]*b[25]; t+=(dpint)a[2]*b[24]; t+=(dpint)a[3]*b[23]; t+=(dpint)a[4]*b[22]; t+=(dpint)a[5]*b[21]; t+=(dpint)a[6]*b[20]; t+=(dpint)a[7]*b[19]; t+=(dpint)a[8]*b[18]; t+=(dpint)a[9]*b[17]; t+=(dpint)a[10]*b[16]; t+=(dpint)a[11]*b[15]; t+=(dpint)a[12]*b[14]; t+=(dpint)a[13]*b[13]; t+=(dpint)a[14]*b[12]; t+=(dpint)a[15]*b[11]; t+=(dpint)a[16]*b[10]; t+=(dpint)a[17]*b[9]; t+=(dpint)a[18]*b[8]; t+=(dpint)a[19]*b[7]; t+=(dpint)a[20]*b[6]; t+=(dpint)a[21]*b[5]; t+=(dpint)a[22]*b[4]; t+=(dpint)a[23]*b[3]; t+=(dpint)a[24]*b[2]; t+=(dpint)a[25]*b[1]; t+=(dpint)v1*(dpint)p25;  t+=(dpint)v2*(dpint)p24;  t+=(dpint)v3*(dpint)p23;  t+=(dpint)v4*(dpint)p22;  t+=(dpint)v5*(dpint)p21;  t+=(dpint)v6*(dpint)p20;  t+=(dpint)v7*(dpint)p19;  t+=(dpint)v8*(dpint)p18;  t+=(dpint)v9*(dpint)p17;  t+=(dpint)v10*(dpint)p16;  t+=(dpint)v11*(dpint)p15;  t+=(dpint)v12*(dpint)p14;  t+=(dpint)v13*(dpint)p13;  t+=(dpint)v14*(dpint)p12;  t+=(dpint)v15*(dpint)p11;  t+=(dpint)v16*(dpint)p10;  t+=(dpint)v17*(dpint)p9;  t+=(dpint)v18*(dpint)p8;  c[0]=((spint)t & mask);  t>>=60;
	t+=(dpint)a[2]*b[25]; t+=(dpint)a[3]*b[24]; t+=(dpint)a[4]*b[23]; t+=(dpint)a[5]*b[22]; t+=(dpint)a[6]*b[21]; t+=(dpint)a[7]*b[20]; t+=(dpint)a[8]*b[19]; t+=(dpint)a[9]*b[18]; t+=(dpint)a[10]*b[17]; t+=(dpint)a[11]*b[16]; t+=(dpint)a[12]*b[15]; t+=(dpint)a[13]*b[14]; t+=(dpint)a[14]*b[13]; t+=(dpint)a[15]*b[12]; t+=(dpint)a[16]*b[11]; t+=(dpint)a[17]*b[10]; t+=(dpint)a[18]*b[9]; t+=(dpint)a[19]*b[8]; t+=(dpint)a[20]*b[7]; t+=(dpint)a[21]*b[6]; t+=(dpint)a[22]*b[5]; t+=(dpint)a[23]*b[4]; t+=(dpint)a[24]*b[3]; t+=(dpint)a[25]*b[2]; t+=(dpint)v2*(dpint)p25;  t+=(dpint)v3*(dpint)p24;  t+=(dpint)v4*(dpint)p23;  t+=(dpint)v5*(dpint)p22;  t+=(dpint)v6*(dpint)p21;  t+=(dpint)v7*(dpint)p20;  t+=(dpint)v8*(dpint)p19;  t+=(dpint)v9*(dpint)p18;  t+=(dpint)v10*(dpint)p17;  t+=(dpint)v11*(dpint)p16;  t+=(dpint)v12*(dpint)p15;  t+=(dpint)v13*(dpint)p14;  t+=(dpint)v14*(dpint)p13;  t+=(dpint)v15*(dpint)p12;  t+=(dpint)v16*(dpint)p11;  t+=(dpint)v17*(dpint)p10;  t+=(dpint)v18*(dpint)p9;  t+=(dpint)v19*(dpint)p8;  c[1]=((spint)t & mask);  t>>=60;
	t+=(dpint)a[3]*b[25]; t+=(dpint)a[4]*b[24]; t+=(dpint)a[5]*b[23]; t+=(dpint)a[6]*b[22]; t+=(dpint)a[7]*b[21]; t+=(dpint)a[8]*b[20]; t+=(dpint)a[9]*b[19]; t+=(dpint)a[10]*b[18]; t+=(dpint)a[11]*b[17]; t+=(dpint)a[12]*b[16]; t+=(dpint)a[13]*b[15]; t+=(dpint)a[14]*b[14]; t+=(dpint)a[15]*b[13]; t+=(dpint)a[16]*b[12]; t+=(dpint)a[17]*b[11]; t+=(dpint)a[18]*b[10]; t+=(dpint)a[19]*b[9]; t+=(dpint)a[20]*b[8]; t+=(dpint)a[21]*b[7]; t+=(dpint)a[22]*b[6]; t+=(dpint)a[23]*b[5]; t+=(dpint)a[24]*b[4]; t+=(dpint)a[25]*b[3]; t+=(dpint)v3*(dpint)p25;  t+=(dpint)v4*(dpint)p24;  t+=(dpint)v5*(dpint)p23;  t+=(dpint)v6*(dpint)p22;  t+=(dpint)v7*(dpint)p21;  t+=(dpint)v8*(dpint)p20;  t+=(dpint)v9*(dpint)p19;  t+=(dpint)v10*(dpint)p18;  t+=(dpint)v11*(dpint)p17;  t+=(dpint)v12*(dpint)p16;  t+=(dpint)v13*(dpint)p15;  t+=(dpint)v14*(dpint)p14;  t+=(dpint)v15*(dpint)p13;  t+=(dpint)v16*(dpint)p12;  t+=(dpint)v17*(dpint)p11;  t+=(dpint)v18*(dpint)p10;  t+=(dpint)v19*(dpint)p9;  t+=(dpint)v20*(dpint)p8;  c[2]=((spint)t & mask);  t>>=60;
	t+=(dpint)a[4]*b[25]; t+=(dpint)a[5]*b[24]; t+=(dpint)a[6]*b[23]; t+=(dpint)a[7]*b[22]; t+=(dpint)a[8]*b[21]; t+=(dpint)a[9]*b[20]; t+=(dpint)a[10]*b[19]; t+=(dpint)a[11]*b[18]; t+=(dpint)a[12]*b[17]; t+=(dpint)a[13]*b[16]; t+=(dpint)a[14]*b[15]; t+=(dpint)a[15]*b[14]; t+=(dpint)a[16]*b[13]; t+=(dpint)a[17]*b[12]; t+=(dpint)a[18]*b[11]; t+=(dpint)a[19]*b[10]; t+=(dpint)a[20]*b[9]; t+=(dpint)a[21]*b[8]; t+=(dpint)a[22]*b[7]; t+=(dpint)a[23]*b[6]; t+=(dpint)a[24]*b[5]; t+=(dpint)a[25]*b[4]; t+=(dpint)v4*(dpint)p25;  t+=(dpint)v5*(dpint)p24;  t+=(dpint)v6*(dpint)p23;  t+=(dpint)v7*(dpint)p22;  t+=(dpint)v8*(dpint)p21;  t+=(dpint)v9*(dpint)p20;  t+=(dpint)v10*(dpint)p19;  t+=(dpint)v11*(dpint)p18;  t+=(dpint)v12*(dpint)p17;  t+=(dpint)v13*(dpint)p16;  t+=(dpint)v14*(dpint)p15;  t+=(dpint)v15*(dpint)p14;  t+=(dpint)v16*(dpint)p13;  t+=(dpint)v17*(dpint)p12;  t+=(dpint)v18*(dpint)p11;  t+=(dpint)v19*(dpint)p10;  t+=(dpint)v20*(dpint)p9;  t+=(dpint)v21*(dpint)p8;  c[3]=((spint)t & mask);  t>>=60;
	t+=(dpint)a[5]*b[25]; t+=(dpint)a[6]*b[24]; t+=(dpint)a[7]*b[23]; t+=(dpint)a[8]*b[22]; t+=(dpint)a[9]*b[21]; t+=(dpint)a[10]*b[20]; t+=(dpint)a[11]*b[19]; t+=(dpint)a[12]*b[18]; t+=(dpint)a[13]*b[17]; t+=(dpint)a[14]*b[16]; t+=(dpint)a[15]*b[15]; t+=(dpint)a[16]*b[14]; t+=(dpint)a[17]*b[13]; t+=(dpint)a[18]*b[12]; t+=(dpint)a[19]*b[11]; t+=(dpint)a[20]*b[10]; t+=(dpint)a[21]*b[9]; t+=(dpint)a[22]*b[8]; t+=(dpint)a[23]*b[7]; t+=(dpint)a[24]*b[6]; t+=(dpint)a[25]*b[5]; t+=(dpint)v5*(dpint)p25;  t+=(dpint)v6*(dpint)p24;  t+=(dpint)v7*(dpint)p23;  t+=(dpint)v8*(dpint)p22;  t+=(dpint)v9*(dpint)p21;  t+=(dpint)v10*(dpint)p20;  t+=(dpint)v11*(dpint)p19;  t+=(dpint)v12*(dpint)p18;  t+=(dpint)v13*(dpint)p17;  t+=(dpint)v14*(dpint)p16;  t+=(dpint)v15*(dpint)p15;  t+=(dpint)v16*(dpint)p14;  t+=(dpint)v17*(dpint)p13;  t+=(dpint)v18*(dpint)p12;  t+=(dpint)v19*(dpint)p11;  t+=(dpint)v20*(dpint)p10;  t+=(dpint)v21*(dpint)p9;  t+=(dpint)v22*(dpint)p8;  c[4]=((spint)t & mask);  t>>=60;
	t+=(dpint)a[6]*b[25]; t+=(dpint)a[7]*b[24]; t+=(dpint)a[8]*b[23]; t+=(dpint)a[9]*b[22]; t+=(dpint)a[10]*b[21]; t+=(dpint)a[11]*b[20]; t+=(dpint)a[12]*b[19]; t+=(dpint)a[13]*b[18]; t+=(dpint)a[14]*b[17]; t+=(dpint)a[15]*b[16]; t+=(dpint)a[16]*b[15]; t+=(dpint)a[17]*b[14]; t+=(dpint)a[18]*b[13]; t+=(dpint)a[19]*b[12]; t+=(dpint)a[20]*b[11]; t+=(dpint)a[21]*b[10]; t+=(dpint)a[22]*b[9]; t+=(dpint)a[23]*b[8]; t+=(dpint)a[24]*b[7]; t+=(dpint)a[25]*b[6]; t+=(dpint)v6*(dpint)p25;  t+=(dpint)v7*(dpint)p24;  t+=(dpint)v8*(dpint)p23;  t+=(dpint)v9*(dpint)p22;  t+=(dpint)v10*(dpint)p21;  t+=(dpint)v11*(dpint)p20;  t+=(dpint)v12*(dpint)p19;  t+=(dpint)v13*(dpint)p18;  t+=(dpint)v14*(dpint)p17;  t+=(dpint)v15*(dpint)p16;  t+=(dpint)v16*(dpint)p15;  t+=(dpint)v17*(dpint)p14;  t+=(dpint)v18*(dpint)p13;  t+=(dpint)v19*(dpint)p12;  t+=(dpint)v20*(dpint)p11;  t+=(dpint)v21*(dpint)p10;  t+=(dpint)v22*(dpint)p9;  t+=(dpint)v23*(dpint)p8;  c[5]=((spint)t & mask);  t>>=60;
	t+=(dpint)a[7]*b[25]; t+=(dpint)a[8]*b[24]; t+=(dpint)a[9]*b[23]; t+=(dpint)a[10]*b[22]; t+=(dpint)a[11]*b[21]; t+=(dpint)a[12]*b[20]; t+=(dpint)a[13]*b[19]; t+=(dpint)a[14]*b[18]; t+=(dpint)a[15]*b[17]; t+=(dpint)a[16]*b[16]; t+=(dpint)a[17]*b[15]; t+=(dpint)a[18]*b[14]; t+=(dpint)a[19]*b[13]; t+=(dpint)a[20]*b[12]; t+=(dpint)a[21]*b[11]; t+=(dpint)a[22]*b[10]; t+=(dpint)a[23]*b[9]; t+=(dpint)a[24]*b[8]; t+=(dpint)a[25]*b[7]; t+=(dpint)v7*(dpint)p25;  t+=(dpint)v8*(dpint)p24;  t+=(dpint)v9*(dpint)p23;  t+=(dpint)v10*(dpint)p22;  t+=(dpint)v11*(dpint)p21;  t+=(dpint)v12*(dpint)p20;  t+=(dpint)v13*(dpint)p19;  t+=(dpint)v14*(dpint)p18;  t+=(dpint)v15*(dpint)p17;  t+=(dpint)v16*(dpint)p16;  t+=(dpint)v17*(dpint)p15;  t+=(dpint)v18*(dpint)p14;  t+=(dpint)v19*(dpint)p13;  t+=(dpint)v20*(dpint)p12;  t+=(dpint)v21*(dpint)p11;  t+=(dpint)v22*(dpint)p10;  t+=(dpint)v23*(dpint)p9;  t+=(dpint)v24*(dpint)p8;  c[6]=((spint)t & mask);  t>>=60;
	t+=(dpint)a[8]*b[25]; t+=(dpint)a[9]*b[24]; t+=(dpint)a[10]*b[23]; t+=(dpint)a[11]*b[22]; t+=(dpint)a[12]*b[21]; t+=(dpint)a[13]*b[20]; t+=(dpint)a[14]*b[19]; t+=(dpint)a[15]*b[18]; t+=(dpint)a[16]*b[17]; t+=(dpint)a[17]*b[16]; t+=(dpint)a[18]*b[15]; t+=(dpint)a[19]*b[14]; t+=(dpint)a[20]*b[13]; t+=(dpint)a[21]*b[12]; t+=(dpint)a[22]*b[11]; t+=(dpint)a[23]*b[10]; t+=(dpint)a[24]*b[9]; t+=(dpint)a[25]*b[8]; t+=(dpint)v8*(dpint)p25;  t+=(dpint)v9*(dpint)p24;  t+=(dpint)v10*(dpint)p23;  t+=(dpint)v11*(dpint)p22;  t+=(dpint)v12*(dpint)p21;  t+=(dpint)v13*(dpint)p20;  t+=(dpint)v14*(dpint)p19;  t+=(dpint)v15*(dpint)p18;  t+=(dpint)v16*(dpint)p17;  t+=(dpint)v17*(dpint)p16;  t+=(dpint)v18*(dpint)p15;  t+=(dpint)v19*(dpint)p14;  t+=(dpint)v20*(dpint)p13;  t+=(dpint)v21*(dpint)p12;  t+=(dpint)v22*(dpint)p11;  t+=(dpint)v23*(dpint)p10;  t+=(dpint)v24*(dpint)p9;  t+=(dpint)v25*(dpint)p8;  c[7]=((spint)t & mask);  t>>=60;
	t+=(dpint)a[9]*b[25]; t+=(dpint)a[10]*b[24]; t+=(dpint)a[11]*b[23]; t+=(dpint)a[12]*b[22]; t+=(dpint)a[13]*b[21]; t+=(dpint)a[14]*b[20]; t+=(dpint)a[15]*b[19]; t+=(dpint)a[16]*b[18]; t+=(dpint)a[17]*b[17]; t+=(dpint)a[18]*b[16]; t+=(dpint)a[19]*b[15]; t+=(dpint)a[20]*b[14]; t+=(dpint)a[21]*b[13]; t+=(dpint)a[22]*b[12]; t+=(dpint)a[23]*b[11]; t+=(dpint)a[24]*b[10]; t+=(dpint)a[25]*b[9]; t+=(dpint)v9*(dpint)p25;  t+=(dpint)v10*(dpint)p24;  t+=(dpint)v11*(dpint)p23;  t+=(dpint)v12*(dpint)p22;  t+=(dpint)v13*(dpint)p21;  t+=(dpint)v14*(dpint)p20;  t+=(dpint)v15*(dpint)p19;  t+=(dpint)v16*(dpint)p18;  t+=(dpint)v17*(dpint)p17;  t+=(dpint)v18*(dpint)p16;  t+=(dpint)v19*(dpint)p15;  t+=(dpint)v20*(dpint)p14;  t+=(dpint)v21*(dpint)p13;  t+=(dpint)v22*(dpint)p12;  t+=(dpint)v23*(dpint)p11;  t+=(dpint)v24*(dpint)p10;  t+=(dpint)v25*(dpint)p9;  c[8]=((spint)t & mask);  t>>=60;
	t+=(dpint)a[10]*b[25]; t+=(dpint)a[11]*b[24]; t+=(dpint)a[12]*b[23]; t+=(dpint)a[13]*b[22]; t+=(dpint)a[14]*b[21]; t+=(dpint)a[15]*b[20]; t+=(dpint)a[16]*b[19]; t+=(dpint)a[17]*b[18]; t+=(dpint)a[18]*b[17]; t+=(dpint)a[19]*b[16]; t+=(dpint)a[20]*b[15]; t+=(dpint)a[21]*b[14]; t+=(dpint)a[22]*b[13]; t+=(dpint)a[23]*b[12]; t+=(dpint)a[24]*b[11]; t+=(dpint)a[25]*b[10]; t+=(dpint)v10*(dpint)p25;  t+=(dpint)v11*(dpint)p24;  t+=(dpint)v12*(dpint)p23;  t+=(dpint)v13*(dpint)p22;  t+=(dpint)v14*(dpint)p21;  t+=(dpint)v15*(dpint)p20;  t+=(dpint)v16*(dpint)p19;  t+=(dpint)v17*(dpint)p18;  t+=(dpint)v18*(dpint)p17;  t+=(dpint)v19*(dpint)p16;  t+=(dpint)v20*(dpint)p15;  t+=(dpint)v21*(dpint)p14;  t+=(dpint)v22*(dpint)p13;  t+=(dpint)v23*(dpint)p12;  t+=(dpint)v24*(dpint)p11;  t+=(dpint)v25*(dpint)p10;  c[9]=((spint)t & mask);  t>>=60;
	t+=(dpint)a[11]*b[25]; t+=(dpint)a[12]*b[24]; t+=(dpint)a[13]*b[23]; t+=(dpint)a[14]*b[22]; t+=(dpint)a[15]*b[21]; t+=(dpint)a[16]*b[20]; t+=(dpint)a[17]*b[19]; t+=(dpint)a[18]*b[18]; t+=(dpint)a[19]*b[17]; t+=(dpint)a[20]*b[16]; t+=(dpint)a[21]*b[15]; t+=(dpint)a[22]*b[14]; t+=(dpint)a[23]*b[13]; t+=(dpint)a[24]*b[12]; t+=(dpint)a[25]*b[11]; t+=(dpint)v11*(dpint)p25;  t+=(dpint)v12*(dpint)p24;  t+=(dpint)v13*(dpint)p23;  t+=(dpint)v14*(dpint)p22;  t+=(dpint)v15*(dpint)p21;  t+=(dpint)v16*(dpint)p20;  t+=(dpint)v17*(dpint)p19;  t+=(dpint)v18*(dpint)p18;  t+=(dpint)v19*(dpint)p17;  t+=(dpint)v20*(dpint)p16;  t+=(dpint)v21*(dpint)p15;  t+=(dpint)v22*(dpint)p14;  t+=(dpint)v23*(dpint)p13;  t+=(dpint)v24*(dpint)p12;  t+=(dpint)v25*(dpint)p11;  c[10]=((spint)t & mask);  t>>=60;
	t+=(dpint)a[12]*b[25]; t+=(dpint)a[13]*b[24]; t+=(dpint)a[14]*b[23]; t+=(dpint)a[15]*b[22]; t+=(dpint)a[16]*b[21]; t+=(dpint)a[17]*b[20]; t+=(dpint)a[18]*b[19]; t+=(dpint)a[19]*b[18]; t+=(dpint)a[20]*b[17]; t+=(dpint)a[21]*b[16]; t+=(dpint)a[22]*b[15]; t+=(dpint)a[23]*b[14]; t+=(dpint)a[24]*b[13]; t+=(dpint)a[25]*b[12]; t+=(dpint)v12*(dpint)p25;  t+=(dpint)v13*(dpint)p24;  t+=(dpint)v14*(dpint)p23;  t+=(dpint)v15*(dpint)p22;  t+=(dpint)v16*(dpint)p21;  t+=(dpint)v17*(dpint)p20;  t+=(dpint)v18*(dpint)p19;  t+=(dpint)v19*(dpint)p18;  t+=(dpint)v20*(dpint)p17;  t+=(dpint)v21*(dpint)p16;  t+=(dpint)v22*(dpint)p15;  t+=(dpint)v23*(dpint)p14;  t+=(dpint)v24*(dpint)p13;  t+=(dpint)v25*(dpint)p12;  c[11]=((spint)t & mask);  t>>=60;
	t+=(dpint)a[13]*b[25]; t+=(dpint)a[14]*b[24]; t+=(dpint)a[15]*b[23]; t+=(dpint)a[16]*b[22]; t+=(dpint)a[17]*b[21]; t+=(dpint)a[18]*b[20]; t+=(dpint)a[19]*b[19]; t+=(dpint)a[20]*b[18]; t+=(dpint)a[21]*b[17]; t+=(dpint)a[22]*b[16]; t+=(dpint)a[23]*b[15]; t+=(dpint)a[24]*b[14]; t+=(dpint)a[25]*b[13]; t+=(dpint)v13*(dpint)p25;  t+=(dpint)v14*(dpint)p24;  t+=(dpint)v15*(dpint)p23;  t+=(dpint)v16*(dpint)p22;  t+=(dpint)v17*(dpint)p21;  t+=(dpint)v18*(dpint)p20;  t+=(dpint)v19*(dpint)p19;  t+=(dpint)v20*(dpint)p18;  t+=(dpint)v21*(dpint)p17;  t+=(dpint)v22*(dpint)p16;  t+=(dpint)v23*(dpint)p15;  t+=(dpint)v24*(dpint)p14;  t+=(dpint)v25*(dpint)p13;  c[12]=((spint)t & mask);  t>>=60;
	t+=(dpint)a[14]*b[25]; t+=(dpint)a[15]*b[24]; t+=(dpint)a[16]*b[23]; t+=(dpint)a[17]*b[22]; t+=(dpint)a[18]*b[21]; t+=(dpint)a[19]*b[20]; t+=(dpint)a[20]*b[19]; t+=(dpint)a[21]*b[18]; t+=(dpint)a[22]*b[17]; t+=(dpint)a[23]*b[16]; t+=(dpint)a[24]*b[15]; t+=(dpint)a[25]*b[14]; t+=(dpint)v14*(dpint)p25;  t+=(dpint)v15*(dpint)p24;  t+=(dpint)v16*(dpint)p23;  t+=(dpint)v17*(dpint)p22;  t+=(dpint)v18*(dpint)p21;  t+=(dpint)v19*(dpint)p20;  t+=(dpint)v20*(dpint)p19;  t+=(dpint)v21*(dpint)p18;  t+=(dpint)v22*(dpint)p17;  t+=(dpint)v23*(dpint)p16;  t+=(dpint)v24*(dpint)p15;  t+=(dpint)v25*(dpint)p14;  c[13]=((spint)t & mask);  t>>=60;
	t+=(dpint)a[15]*b[25]; t+=(dpint)a[16]*b[24]; t+=(dpint)a[17]*b[23]; t+=(dpint)a[18]*b[22]; t+=(dpint)a[19]*b[21]; t+=(dpint)a[20]*b[20]; t+=(dpint)a[21]*b[19]; t+=(dpint)a[22]*b[18]; t+=(dpint)a[23]*b[17]; t+=(dpint)a[24]*b[16]; t+=(dpint)a[25]*b[15]; t+=(dpint)v15*(dpint)p25;  t+=(dpint)v16*(dpint)p24;  t+=(dpint)v17*(dpint)p23;  t+=(dpint)v18*(dpint)p22;  t+=(dpint)v19*(dpint)p21;  t+=(dpint)v20*(dpint)p20;  t+=(dpint)v21*(dpint)p19;  t+=(dpint)v22*(dpint)p18;  t+=(dpint)v23*(dpint)p17;  t+=(dpint)v24*(dpint)p16;  t+=(dpint)v25*(dpint)p15;  c[14]=((spint)t & mask);  t>>=60;
	t+=(dpint)a[16]*b[25]; t+=(dpint)a[17]*b[24]; t+=(dpint)a[18]*b[23]; t+=(dpint)a[19]*b[22]; t+=(dpint)a[20]*b[21]; t+=(dpint)a[21]*b[20]; t+=(dpint)a[22]*b[19]; t+=(dpint)a[23]*b[18]; t+=(dpint)a[24]*b[17]; t+=(dpint)a[25]*b[16]; t+=(dpint)v16*(dpint)p25;  t+=(dpint)v17*(dpint)p24;  t+=(dpint)v18*(dpint)p23;  t+=(dpint)v19*(dpint)p22;  t+=(dpint)v20*(dpint)p21;  t+=(dpint)v21*(dpint)p20;  t+=(dpint)v22*(dpint)p19;  t+=(dpint)v23*(dpint)p18;  t+=(dpint)v24*(dpint)p17;  t+=(dpint)v25*(dpint)p16;  c[15]=((spint)t & mask);  t>>=60;
	t+=(dpint)a[17]*b[25]; t+=(dpint)a[18]*b[24]; t+=(dpint)a[19]*b[23]; t+=(dpint)a[20]*b[22]; t+=(dpint)a[21]*b[21]; t+=(dpint)a[22]*b[20]; t+=(dpint)a[23]*b[19]; t+=(dpint)a[24]*b[18]; t+=(dpint)a[25]*b[17]; t+=(dpint)v17*(dpint)p25;  t+=(dpint)v18*(dpint)p24;  t+=(dpint)v19*(dpint)p23;  t+=(dpint)v20*(dpint)p22;  t+=(dpint)v21*(dpint)p21;  t+=(dpint)v22*(dpint)p20;  t+=(dpint)v23*(dpint)p19;  t+=(dpint)v24*(dpint)p18;  t+=(dpint)v25*(dpint)p17;  c[16]=((spint)t & mask);  t>>=60;
	t+=(dpint)a[18]*b[25]; t+=(dpint)a[19]*b[24]; t+=(dpint)a[20]*b[23]; t+=(dpint)a[21]*b[22]; t+=(dpint)a[22]*b[21]; t+=(dpint)a[23]*b[20]; t+=(dpint)a[24]*b[19]; t+=(dpint)a[25]*b[18]; t+=(dpint)v18*(dpint)p25;  t+=(dpint)v19*(dpint)p24;  t+=(dpint)v20*(dpint)p23;  t+=(dpint)v21*(dpint)p22;  t+=(dpint)v22*(dpint)p21;  t+=(dpint)v23*(dpint)p20;  t+=(dpint)v24*(dpint)p19;  t+=(dpint)v25*(dpint)p18;  c[17]=((spint)t & mask);  t>>=60;
	t+=(dpint)a[19]*b[25]; t+=(dpint)a[20]*b[24]; t+=(dpint)a[21]*b[23]; t+=(dpint)a[22]*b[22]; t+=(dpint)a[23]*b[21]; t+=(dpint)a[24]*b[20]; t+=(dpint)a[25]*b[19]; t+=(dpint)v19*(dpint)p25;  t+=(dpint)v20*(dpint)p24;  t+=(dpint)v21*(dpint)p23;  t+=(dpint)v22*(dpint)p22;  t+=(dpint)v23*(dpint)p21;  t+=(dpint)v24*(dpint)p20;  t+=(dpint)v25*(dpint)p19;  c[18]=((spint)t & mask);  t>>=60;
	t+=(dpint)a[20]*b[25]; t+=(dpint)a[21]*b[24]; t+=(dpint)a[22]*b[23]; t+=(dpint)a[23]*b[22]; t+=(dpint)a[24]*b[21]; t+=(dpint)a[25]*b[20]; t+=(dpint)v20*(dpint)p25;  t+=(dpint)v21*(dpint)p24;  t+=(dpint)v22*(dpint)p23;  t+=(dpint)v23*(dpint)p22;  t+=(dpint)v24*(dpint)p21;  t+=(dpint)v25*(dpint)p20;  c[19]=((spint)t & mask);  t>>=60;
	t+=(dpint)a[21]*b[25]; t+=(dpint)a[22]*b[24]; t+=(dpint)a[23]*b[23]; t+=(dpint)a[24]*b[22]; t+=(dpint)a[25]*b[21]; t+=(dpint)v21*(dpint)p25;  t+=(dpint)v22*(dpint)p24;  t+=(dpint)v23*(dpint)p23;  t+=(dpint)v24*(dpint)p22;  t+=(dpint)v25*(dpint)p21;  c[20]=((spint)t & mask);  t>>=60;
	t+=(dpint)a[22]*b[25]; t+=(dpint)a[23]*b[24]; t+=(dpint)a[24]*b[23]; t+=(dpint)a[25]*b[22]; t+=(dpint)v22*(dpint)p25;  t+=(dpint)v23*(dpint)p24;  t+=(dpint)v24*(dpint)p23;  t+=(dpint)v25*(dpint)p22;  c[21]=((spint)t & mask);  t>>=60;
	t+=(dpint)a[23]*b[25]; t+=(dpint)a[24]*b[24]; t+=(dpint)a[25]*b[23]; t+=(dpint)v23*(dpint)p25;  t+=(dpint)v24*(dpint)p24;  t+=(dpint)v25*(dpint)p23;  c[22]=((spint)t & mask);  t>>=60;
	t+=(dpint)a[24]*b[25]; t+=(dpint)a[25]*b[24]; t+=(dpint)v24*(dpint)p25;  t+=(dpint)v25*(dpint)p24;  c[23]=((spint)t & mask);  t>>=60;
	t+=(dpint)a[25]*b[25]; t+=(dpint)v25*(dpint)p25;  c[24]=((spint)t & mask);  t>>=60;
	c[25] = (spint)t;
}

// Modular squaring, c=a*a  mod 2p
static void modsqr(const spint *a,spint *c) {
	dpint tot;
	dpint t=0;
	spint p8=0xf7b456c00000000u;
	spint p9=0xb1df2a74f745f71u;
	spint p10=0x530814e9c3615eau;
	spint p11=0xa281e3cd1244524u;
	spint p12=0x3afdae93fda6645u;
	spint p13=0xcb3a5035c534b5fu;
	spint p14=0xf8cd6ed92b85bd0u;
	spint p15=0xb3e2fa38f5419bau;
	spint p16=0xf81c420b2dfbb3fu;
	spint p17=0xf58123de8fab63eu;
	spint p18=0x3a493432f085476u;
	spint p19=0x821a8511c268f4cu;
	spint p20=0xf3ede30e07607a2u;
	spint p21=0xc051219e91bdfbfu;
	spint p22=0xf71da19e514541bu;
	spint p23=0xe0e783f6a886397u;
	spint p24=0x50ed1445554f51cu;
	spint p25=0x22606deb0u;
	spint q=((spint)1<<60u); // q is unsaturated radix 
	spint mask=(spint)(q-(spint)1);
	tot=(dpint)a[0]*a[0]; t=tot; spint v0=((spint)t & mask); t>>=60;
	tot=(dpint)a[0]*a[1]; tot*=2; t+=tot;  spint v1=((spint)t & mask); t>>=60;
	tot=(dpint)a[0]*a[2]; tot*=2; tot+=(dpint)a[1]*a[1]; t+=tot;  spint v2=((spint)t & mask); t>>=60;
	tot=(dpint)a[0]*a[3]; tot+=(dpint)a[1]*a[2]; tot*=2; t+=tot;  spint v3=((spint)t & mask); t>>=60;
	tot=(dpint)a[0]*a[4]; tot+=(dpint)a[1]*a[3]; tot*=2; tot+=(dpint)a[2]*a[2]; t+=tot;  spint v4=((spint)t & mask); t>>=60;
	tot=(dpint)a[0]*a[5]; tot+=(dpint)a[1]*a[4]; tot+=(dpint)a[2]*a[3]; tot*=2; t+=tot;  spint v5=((spint)t & mask); t>>=60;
	tot=(dpint)a[0]*a[6]; tot+=(dpint)a[1]*a[5]; tot+=(dpint)a[2]*a[4]; tot*=2; tot+=(dpint)a[3]*a[3]; t+=tot;  spint v6=((spint)t & mask); t>>=60;
	tot=(dpint)a[0]*a[7]; tot+=(dpint)a[1]*a[6]; tot+=(dpint)a[2]*a[5]; tot+=(dpint)a[3]*a[4]; tot*=2; t+=tot;  spint v7=((spint)t & mask); t>>=60;
	tot=(dpint)a[0]*a[8]; tot+=(dpint)a[1]*a[7]; tot+=(dpint)a[2]*a[6]; tot+=(dpint)a[3]*a[5]; tot*=2; tot+=(dpint)a[4]*a[4]; t+=tot;  t+=(dpint)v0*p8;  spint v8=((spint)t & mask); t>>=60;
	tot=(dpint)a[0]*a[9]; tot+=(dpint)a[1]*a[8]; tot+=(dpint)a[2]*a[7]; tot+=(dpint)a[3]*a[6]; tot+=(dpint)a[4]*a[5]; tot*=2; t+=tot;  t+=(dpint)v0*p9;  t+=(dpint)v1*p8;  spint v9=((spint)t & mask); t>>=60;
	tot=(dpint)a[0]*a[10]; tot+=(dpint)a[1]*a[9]; tot+=(dpint)a[2]*a[8]; tot+=(dpint)a[3]*a[7]; tot+=(dpint)a[4]*a[6]; tot*=2; tot+=(dpint)a[5]*a[5]; t+=tot;  t+=(dpint)v0*p10;  t+=(dpint)v1*p9;  t+=(dpint)v2*p8;  spint v10=((spint)t & mask); t>>=60;
	tot=(dpint)a[0]*a[11]; tot+=(dpint)a[1]*a[10]; tot+=(dpint)a[2]*a[9]; tot+=(dpint)a[3]*a[8]; tot+=(dpint)a[4]*a[7]; tot+=(dpint)a[5]*a[6]; tot*=2; t+=tot;  t+=(dpint)v0*p11;  t+=(dpint)v1*p10;  t+=(dpint)v2*p9;  t+=(dpint)v3*p8;  spint v11=((spint)t & mask); t>>=60;
	tot=(dpint)a[0]*a[12]; tot+=(dpint)a[1]*a[11]; tot+=(dpint)a[2]*a[10]; tot+=(dpint)a[3]*a[9]; tot+=(dpint)a[4]*a[8]; tot+=(dpint)a[5]*a[7]; tot*=2; tot+=(dpint)a[6]*a[6]; t+=tot;  t+=(dpint)v0*p12;  t+=(dpint)v1*p11;  t+=(dpint)v2*p10;  t+=(dpint)v3*p9;  t+=(dpint)v4*p8;  spint v12=((spint)t & mask); t>>=60;
	tot=(dpint)a[0]*a[13]; tot+=(dpint)a[1]*a[12]; tot+=(dpint)a[2]*a[11]; tot+=(dpint)a[3]*a[10]; tot+=(dpint)a[4]*a[9]; tot+=(dpint)a[5]*a[8]; tot+=(dpint)a[6]*a[7]; tot*=2; t+=tot;  t+=(dpint)v0*p13;  t+=(dpint)v1*p12;  t+=(dpint)v2*p11;  t+=(dpint)v3*p10;  t+=(dpint)v4*p9;  t+=(dpint)v5*p8;  spint v13=((spint)t & mask); t>>=60;
	tot=(dpint)a[0]*a[14]; tot+=(dpint)a[1]*a[13]; tot+=(dpint)a[2]*a[12]; tot+=(dpint)a[3]*a[11]; tot+=(dpint)a[4]*a[10]; tot+=(dpint)a[5]*a[9]; tot+=(dpint)a[6]*a[8]; tot*=2; tot+=(dpint)a[7]*a[7]; t+=tot;  t+=(dpint)v0*p14;  t+=(dpint)v1*p13;  t+=(dpint)v2*p12;  t+=(dpint)v3*p11;  t+=(dpint)v4*p10;  t+=(dpint)v5*p9;  t+=(dpint)v6*p8;  spint v14=((spint)t & mask); t>>=60;
	tot=(dpint)a[0]*a[15]; tot+=(dpint)a[1]*a[14]; tot+=(dpint)a[2]*a[13]; tot+=(dpint)a[3]*a[12]; tot+=(dpint)a[4]*a[11]; tot+=(dpint)a[5]*a[10]; tot+=(dpint)a[6]*a[9]; tot+=(dpint)a[7]*a[8]; tot*=2; t+=tot;  t+=(dpint)v0*p15;  t+=(dpint)v1*p14;  t+=(dpint)v2*p13;  t+=(dpint)v3*p12;  t+=(dpint)v4*p11;  t+=(dpint)v5*p10;  t+=(dpint)v6*p9;  t+=(dpint)v7*p8;  spint v15=((spint)t & mask); t>>=60;
	tot=(dpint)a[0]*a[16]; tot+=(dpint)a[1]*a[15]; tot+=(dpint)a[2]*a[14]; tot+=(dpint)a[3]*a[13]; tot+=(dpint)a[4]*a[12]; tot+=(dpint)a[5]*a[11]; tot+=(dpint)a[6]*a[10]; tot+=(dpint)a[7]*a[9]; tot*=2; tot+=(dpint)a[8]*a[8]; t+=tot;  t+=(dpint)v0*p16;  t+=(dpint)v1*p15;  t+=(dpint)v2*p14;  t+=(dpint)v3*p13;  t+=(dpint)v4*p12;  t+=(dpint)v5*p11;  t+=(dpint)v6*p10;  t+=(dpint)v7*p9;  t+=(dpint)v8*p8;  spint v16=((spint)t & mask); t>>=60;
	tot=(dpint)a[0]*a[17]; tot+=(dpint)a[1]*a[16]; tot+=(dpint)a[2]*a[15]; tot+=(dpint)a[3]*a[14]; tot+=(dpint)a[4]*a[13]; tot+=(dpint)a[5]*a[12]; tot+=(dpint)a[6]*a[11]; tot+=(dpint)a[7]*a[10]; tot+=(dpint)a[8]*a[9]; tot*=2; t+=tot;  t+=(dpint)v0*p17;  t+=(dpint)v1*p16;  t+=(dpint)v2*p15;  t+=(dpint)v3*p14;  t+=(dpint)v4*p13;  t+=(dpint)v5*p12;  t+=(dpint)v6*p11;  t+=(dpint)v7*p10;  t+=(dpint)v8*p9;  t+=(dpint)v9*p8;  spint v17=((spint)t & mask); t>>=60;
	tot=(dpint)a[0]*a[18]; tot+=(dpint)a[1]*a[17]; tot+=(dpint)a[2]*a[16]; tot+=(dpint)a[3]*a[15]; tot+=(dpint)a[4]*a[14]; tot+=(dpint)a[5]*a[13]; tot+=(dpint)a[6]*a[12]; tot+=(dpint)a[7]*a[11]; tot+=(dpint)a[8]*a[10]; tot*=2; tot+=(dpint)a[9]*a[9]; t+=tot;  t+=(dpint)v0*p18;  t+=(dpint)v1*p17;  t+=(dpint)v2*p16;  t+=(dpint)v3*p15;  t+=(dpint)v4*p14;  t+=(dpint)v5*p13;  t+=(dpint)v6*p12;  t+=(dpint)v7*p11;  t+=(dpint)v8*p10;  t+=(dpint)v9*p9;  t+=(dpint)v10*p8;  spint v18=((spint)t & mask); t>>=60;
	tot=(dpint)a[0]*a[19]; tot+=(dpint)a[1]*a[18]; tot+=(dpint)a[2]*a[17]; tot+=(dpint)a[3]*a[16]; tot+=(dpint)a[4]*a[15]; tot+=(dpint)a[5]*a[14]; tot+=(dpint)a[6]*a[13]; tot+=(dpint)a[7]*a[12]; tot+=(dpint)a[8]*a[11]; tot+=(dpint)a[9]*a[10]; tot*=2; t+=tot;  t+=(dpint)v0*p19;  t+=(dpint)v1*p18;  t+=(dpint)v2*p17;  t+=(dpint)v3*p16;  t+=(dpint)v4*p15;  t+=(dpint)v5*p14;  t+=(dpint)v6*p13;  t+=(dpint)v7*p12;  t+=(dpint)v8*p11;  t+=(dpint)v9*p10;  t+=(dpint)v10*p9;  t+=(dpint)v11*p8;  spint v19=((spint)t & mask); t>>=60;
	tot=(dpint)a[0]*a[20]; tot+=(dpint)a[1]*a[19]; tot+=(dpint)a[2]*a[18]; tot+=(dpint)a[3]*a[17]; tot+=(dpint)a[4]*a[16]; tot+=(dpint)a[5]*a[15]; tot+=(dpint)a[6]*a[14]; tot+=(dpint)a[7]*a[13]; tot+=(dpint)a[8]*a[12]; tot+=(dpint)a[9]*a[11]; tot*=2; tot+=(dpint)a[10]*a[10]; t+=tot;  t+=(dpint)v0*p20;  t+=(dpint)v1*p19;  t+=(dpint)v2*p18;  t+=(dpint)v3*p17;  t+=(dpint)v4*p16;  t+=(dpint)v5*p15;  t+=(dpint)v6*p14;  t+=(dpint)v7*p13;  t+=(dpint)v8*p12;  t+=(dpint)v9*p11;  t+=(dpint)v10*p10;  t+=(dpint)v11*p9;  t+=(dpint)v12*p8;  spint v20=((spint)t & mask); t>>=60;
	tot=(dpint)a[0]*a[21]; tot+=(dpint)a[1]*a[20]; tot+=(dpint)a[2]*a[19]; tot+=(dpint)a[3]*a[18]; tot+=(dpint)a[4]*a[17]; tot+=(dpint)a[5]*a[16]; tot+=(dpint)a[6]*a[15]; tot+=(dpint)a[7]*a[14]; tot+=(dpint)a[8]*a[13]; tot+=(dpint)a[9]*a[12]; tot+=(dpint)a[10]*a[11]; tot*=2; t+=tot;  t+=(dpint)v0*p21;  t+=(dpint)v1*p20;  t+=(dpint)v2*p19;  t+=(dpint)v3*p18;  t+=(dpint)v4*p17;  t+=(dpint)v5*p16;  t+=(dpint)v6*p15;  t+=(dpint)v7*p14;  t+=(dpint)v8*p13;  t+=(dpint)v9*p12;  t+=(dpint)v10*p11;  t+=(dpint)v11*p10;  t+=(dpint)v12*p9;  t+=(dpint)v13*p8;  spint v21=((spint)t & mask); t>>=60;
	tot=(dpint)a[0]*a[22]; tot+=(dpint)a[1]*a[21]; tot+=(dpint)a[2]*a[20]; tot+=(dpint)a[3]*a[19]; tot+=(dpint)a[4]*a[18]; tot+=(dpint)a[5]*a[17]; tot+=(dpint)a[6]*a[16]; tot+=(dpint)a[7]*a[15]; tot+=(dpint)a[8]*a[14]; tot+=(dpint)a[9]*a[13]; tot+=(dpint)a[10]*a[12]; tot*=2; tot+=(dpint)a[11]*a[11]; t+=tot;  t+=(dpint)v0*p22;  t+=(dpint)v1*p21;  t+=(dpint)v2*p20;  t+=(dpint)v3*p19;  t+=(dpint)v4*p18;  t+=(dpint)v5*p17;  t+=(dpint)v6*p16;  t+=(dpint)v7*p15;  t+=(dpint)v8*p14;  t+=(dpint)v9*p13;  t+=(dpint)v10*p12;  t+=(dpint)v11*p11;  t+=(dpint)v12*p10;  t+=(dpint)v13*p9;  t+=(dpint)v14*p8;  spint v22=((spint)t & mask); t>>=60;
	tot=(dpint)a[0]*a[23]; tot+=(dpint)a[1]*a[22]; tot+=(dpint)a[2]*a[21]; tot+=(dpint)a[3]*a[20]; tot+=(dpint)a[4]*a[19]; tot+=(dpint)a[5]*a[18]; tot+=(dpint)a[6]*a[17]; tot+=(dpint)a[7]*a[16]; tot+=(dpint)a[8]*a[15]; tot+=(dpint)a[9]*a[14]; tot+=(dpint)a[10]*a[13]; tot+=(dpint)a[11]*a[12]; tot*=2; t+=tot;  t+=(dpint)v0*p23;  t+=(dpint)v1*p22;  t+=(dpint)v2*p21;  t+=(dpint)v3*p20;  t+=(dpint)v4*p19;  t+=(dpint)v5*p18;  t+=(dpint)v6*p17;  t+=(dpint)v7*p16;  t+=(dpint)v8*p15;  t+=(dpint)v9*p14;  t+=(dpint)v10*p13;  t+=(dpint)v11*p12;  t+=(dpint)v12*p11;  t+=(dpint)v13*p10;  t+=(dpint)v14*p9;  t+=(dpint)v15*p8;  spint v23=((spint)t & mask); t>>=60;
	tot=(dpint)a[0]*a[24]; tot+=(dpint)a[1]*a[23]; tot+=(dpint)a[2]*a[22]; tot+=(dpint)a[3]*a[21]; tot+=(dpint)a[4]*a[20]; tot+=(dpint)a[5]*a[19]; tot+=(dpint)a[6]*a[18]; tot+=(dpint)a[7]*a[17]; tot+=(dpint)a[8]*a[16]; tot+=(dpint)a[9]*a[15]; tot+=(dpint)a[10]*a[14]; tot+=(dpint)a[11]*a[13]; tot*=2; tot+=(dpint)a[12]*a[12]; t+=tot;  t+=(dpint)v0*p24;  t+=(dpint)v1*p23;  t+=(dpint)v2*p22;  t+=(dpint)v3*p21;  t+=(dpint)v4*p20;  t+=(dpint)v5*p19;  t+=(dpint)v6*p18;  t+=(dpint)v7*p17;  t+=(dpint)v8*p16;  t+=(dpint)v9*p15;  t+=(dpint)v10*p14;  t+=(dpint)v11*p13;  t+=(dpint)v12*p12;  t+=(dpint)v13*p11;  t+=(dpint)v14*p10;  t+=(dpint)v15*p9;  t+=(dpint)v16*p8;  spint v24=((spint)t & mask); t>>=60;
	tot=(dpint)a[0]*a[25]; tot+=(dpint)a[1]*a[24]; tot+=(dpint)a[2]*a[23]; tot+=(dpint)a[3]*a[22]; tot+=(dpint)a[4]*a[21]; tot+=(dpint)a[5]*a[20]; tot+=(dpint)a[6]*a[19]; tot+=(dpint)a[7]*a[18]; tot+=(dpint)a[8]*a[17]; tot+=(dpint)a[9]*a[16]; tot+=(dpint)a[10]*a[15]; tot+=(dpint)a[11]*a[14]; tot+=(dpint)a[12]*a[13]; tot*=2; t+=tot;  t+=(dpint)v0*p25;  t+=(dpint)v1*p24;  t+=(dpint)v2*p23;  t+=(dpint)v3*p22;  t+=(dpint)v4*p21;  t+=(dpint)v5*p20;  t+=(dpint)v6*p19;  t+=(dpint)v7*p18;  t+=(dpint)v8*p17;  t+=(dpint)v9*p16;  t+=(dpint)v10*p15;  t+=(dpint)v11*p14;  t+=(dpint)v12*p13;  t+=(dpint)v13*p12;  t+=(dpint)v14*p11;  t+=(dpint)v15*p10;  t+=(dpint)v16*p9;  t+=(dpint)v17*p8;  spint v25=((spint)t & mask); t>>=60;
	tot=(dpint)a[1]*a[25]; tot+=(dpint)a[2]*a[24]; tot+=(dpint)a[3]*a[23]; tot+=(dpint)a[4]*a[22]; tot+=(dpint)a[5]*a[21]; tot+=(dpint)a[6]*a[20]; tot+=(dpint)a[7]*a[19]; tot+=(dpint)a[8]*a[18]; tot+=(dpint)a[9]*a[17]; tot+=(dpint)a[10]*a[16]; tot+=(dpint)a[11]*a[15]; tot+=(dpint)a[12]*a[14]; tot*=2; tot+=(dpint)a[13]*a[13]; t+=tot;  t+=(dpint)v1*p25;  t+=(dpint)v2*p24;  t+=(dpint)v3*p23;  t+=(dpint)v4*p22;  t+=(dpint)v5*p21;  t+=(dpint)v6*p20;  t+=(dpint)v7*p19;  t+=(dpint)v8*p18;  t+=(dpint)v9*p17;  t+=(dpint)v10*p16;  t+=(dpint)v11*p15;  t+=(dpint)v12*p14;  t+=(dpint)v13*p13;  t+=(dpint)v14*p12;  t+=(dpint)v15*p11;  t+=(dpint)v16*p10;  t+=(dpint)v17*p9;  t+=(dpint)v18*p8;  c[0]=((spint)t & mask);  t>>=60;
	tot=(dpint)a[2]*a[25]; tot+=(dpint)a[3]*a[24]; tot+=(dpint)a[4]*a[23]; tot+=(dpint)a[5]*a[22]; tot+=(dpint)a[6]*a[21]; tot+=(dpint)a[7]*a[20]; tot+=(dpint)a[8]*a[19]; tot+=(dpint)a[9]*a[18]; tot+=(dpint)a[10]*a[17]; tot+=(dpint)a[11]*a[16]; tot+=(dpint)a[12]*a[15]; tot+=(dpint)a[13]*a[14]; tot*=2; t+=tot;  t+=(dpint)v2*p25;  t+=(dpint)v3*p24;  t+=(dpint)v4*p23;  t+=(dpint)v5*p22;  t+=(dpint)v6*p21;  t+=(dpint)v7*p20;  t+=(dpint)v8*p19;  t+=(dpint)v9*p18;  t+=(dpint)v10*p17;  t+=(dpint)v11*p16;  t+=(dpint)v12*p15;  t+=(dpint)v13*p14;  t+=(dpint)v14*p13;  t+=(dpint)v15*p12;  t+=(dpint)v16*p11;  t+=(dpint)v17*p10;  t+=(dpint)v18*p9;  t+=(dpint)v19*p8;  c[1]=((spint)t & mask);  t>>=60;
	tot=(dpint)a[3]*a[25]; tot+=(dpint)a[4]*a[24]; tot+=(dpint)a[5]*a[23]; tot+=(dpint)a[6]*a[22]; tot+=(dpint)a[7]*a[21]; tot+=(dpint)a[8]*a[20]; tot+=(dpint)a[9]*a[19]; tot+=(dpint)a[10]*a[18]; tot+=(dpint)a[11]*a[17]; tot+=(dpint)a[12]*a[16]; tot+=(dpint)a[13]*a[15]; tot*=2; tot+=(dpint)a[14]*a[14]; t+=tot;  t+=(dpint)v3*p25;  t+=(dpint)v4*p24;  t+=(dpint)v5*p23;  t+=(dpint)v6*p22;  t+=(dpint)v7*p21;  t+=(dpint)v8*p20;  t+=(dpint)v9*p19;  t+=(dpint)v10*p18;  t+=(dpint)v11*p17;  t+=(dpint)v12*p16;  t+=(dpint)v13*p15;  t+=(dpint)v14*p14;  t+=(dpint)v15*p13;  t+=(dpint)v16*p12;  t+=(dpint)v17*p11;  t+=(dpint)v18*p10;  t+=(dpint)v19*p9;  t+=(dpint)v20*p8;  c[2]=((spint)t & mask);  t>>=60;
	tot=(dpint)a[4]*a[25]; tot+=(dpint)a[5]*a[24]; tot+=(dpint)a[6]*a[23]; tot+=(dpint)a[7]*a[22]; tot+=(dpint)a[8]*a[21]; tot+=(dpint)a[9]*a[20]; tot+=(dpint)a[10]*a[19]; tot+=(dpint)a[11]*a[18]; tot+=(dpint)a[12]*a[17]; tot+=(dpint)a[13]*a[16]; tot+=(dpint)a[14]*a[15]; tot*=2; t+=tot;  t+=(dpint)v4*p25;  t+=(dpint)v5*p24;  t+=(dpint)v6*p23;  t+=(dpint)v7*p22;  t+=(dpint)v8*p21;  t+=(dpint)v9*p20;  t+=(dpint)v10*p19;  t+=(dpint)v11*p18;  t+=(dpint)v12*p17;  t+=(dpint)v13*p16;  t+=(dpint)v14*p15;  t+=(dpint)v15*p14;  t+=(dpint)v16*p13;  t+=(dpint)v17*p12;  t+=(dpint)v18*p11;  t+=(dpint)v19*p10;  t+=(dpint)v20*p9;  t+=(dpint)v21*p8;  c[3]=((spint)t & mask);  t>>=60;
	tot=(dpint)a[5]*a[25]; tot+=(dpint)a[6]*a[24]; tot+=(dpint)a[7]*a[23]; tot+=(dpint)a[8]*a[22]; tot+=(dpint)a[9]*a[21]; tot+=(dpint)a[10]*a[20]; tot+=(dpint)a[11]*a[19]; tot+=(dpint)a[12]*a[18]; tot+=(dpint)a[13]*a[17]; tot+=(dpint)a[14]*a[16]; tot*=2; tot+=(dpint)a[15]*a[15]; t+=tot;  t+=(dpint)v5*p25;  t+=(dpint)v6*p24;  t+=(dpint)v7*p23;  t+=(dpint)v8*p22;  t+=(dpint)v9*p21;  t+=(dpint)v10*p20;  t+=(dpint)v11*p19;  t+=(dpint)v12*p18;  t+=(dpint)v13*p17;  t+=(dpint)v14*p16;  t+=(dpint)v15*p15;  t+=(dpint)v16*p14;  t+=(dpint)v17*p13;  t+=(dpint)v18*p12;  t+=(dpint)v19*p11;  t+=(dpint)v20*p10;  t+=(dpint)v21*p9;  t+=(dpint)v22*p8;  c[4]=((spint)t & mask);  t>>=60;
	tot=(dpint)a[6]*a[25]; tot+=(dpint)a[7]*a[24]; tot+=(dpint)a[8]*a[23]; tot+=(dpint)a[9]*a[22]; tot+=(dpint)a[10]*a[21]; tot+=(dpint)a[11]*a[20]; tot+=(dpint)a[12]*a[19]; tot+=(dpint)a[13]*a[18]; tot+=(dpint)a[14]*a[17]; tot+=(dpint)a[15]*a[16]; tot*=2; t+=tot;  t+=(dpint)v6*p25;  t+=(dpint)v7*p24;  t+=(dpint)v8*p23;  t+=(dpint)v9*p22;  t+=(dpint)v10*p21;  t+=(dpint)v11*p20;  t+=(dpint)v12*p19;  t+=(dpint)v13*p18;  t+=(dpint)v14*p17;  t+=(dpint)v15*p16;  t+=(dpint)v16*p15;  t+=(dpint)v17*p14;  t+=(dpint)v18*p13;  t+=(dpint)v19*p12;  t+=(dpint)v20*p11;  t+=(dpint)v21*p10;  t+=(dpint)v22*p9;  t+=(dpint)v23*p8;  c[5]=((spint)t & mask);  t>>=60;
	tot=(dpint)a[7]*a[25]; tot+=(dpint)a[8]*a[24]; tot+=(dpint)a[9]*a[23]; tot+=(dpint)a[10]*a[22]; tot+=(dpint)a[11]*a[21]; tot+=(dpint)a[12]*a[20]; tot+=(dpint)a[13]*a[19]; tot+=(dpint)a[14]*a[18]; tot+=(dpint)a[15]*a[17]; tot*=2; tot+=(dpint)a[16]*a[16]; t+=tot;  t+=(dpint)v7*p25;  t+=(dpint)v8*p24;  t+=(dpint)v9*p23;  t+=(dpint)v10*p22;  t+=(dpint)v11*p21;  t+=(dpint)v12*p20;  t+=(dpint)v13*p19;  t+=(dpint)v14*p18;  t+=(dpint)v15*p17;  t+=(dpint)v16*p16;  t+=(dpint)v17*p15;  t+=(dpint)v18*p14;  t+=(dpint)v19*p13;  t+=(dpint)v20*p12;  t+=(dpint)v21*p11;  t+=(dpint)v22*p10;  t+=(dpint)v23*p9;  t+=(dpint)v24*p8;  c[6]=((spint)t & mask);  t>>=60;
	tot=(dpint)a[8]*a[25]; tot+=(dpint)a[9]*a[24]; tot+=(dpint)a[10]*a[23]; tot+=(dpint)a[11]*a[22]; tot+=(dpint)a[12]*a[21]; tot+=(dpint)a[13]*a[20]; tot+=(dpint)a[14]*a[19]; tot+=(dpint)a[15]*a[18]; tot+=(dpint)a[16]*a[17]; tot*=2; t+=tot;  t+=(dpint)v8*p25;  t+=(dpint)v9*p24;  t+=(dpint)v10*p23;  t+=(dpint)v11*p22;  t+=(dpint)v12*p21;  t+=(dpint)v13*p20;  t+=(dpint)v14*p19;  t+=(dpint)v15*p18;  t+=(dpint)v16*p17;  t+=(dpint)v17*p16;  t+=(dpint)v18*p15;  t+=(dpint)v19*p14;  t+=(dpint)v20*p13;  t+=(dpint)v21*p12;  t+=(dpint)v22*p11;  t+=(dpint)v23*p10;  t+=(dpint)v24*p9;  t+=(dpint)v25*p8;  c[7]=((spint)t & mask);  t>>=60;
	tot=(dpint)a[9]*a[25]; tot+=(dpint)a[10]*a[24]; tot+=(dpint)a[11]*a[23]; tot+=(dpint)a[12]*a[22]; tot+=(dpint)a[13]*a[21]; tot+=(dpint)a[14]*a[20]; tot+=(dpint)a[15]*a[19]; tot+=(dpint)a[16]*a[18]; tot*=2; tot+=(dpint)a[17]*a[17]; t+=tot;  t+=(dpint)v9*p25;  t+=(dpint)v10*p24;  t+=(dpint)v11*p23;  t+=(dpint)v12*p22;  t+=(dpint)v13*p21;  t+=(dpint)v14*p20;  t+=(dpint)v15*p19;  t+=(dpint)v16*p18;  t+=(dpint)v17*p17;  t+=(dpint)v18*p16;  t+=(dpint)v19*p15;  t+=(dpint)v20*p14;  t+=(dpint)v21*p13;  t+=(dpint)v22*p12;  t+=(dpint)v23*p11;  t+=(dpint)v24*p10;  t+=(dpint)v25*p9;  c[8]=((spint)t & mask);  t>>=60;
	tot=(dpint)a[10]*a[25]; tot+=(dpint)a[11]*a[24]; tot+=(dpint)a[12]*a[23]; tot+=(dpint)a[13]*a[22]; tot+=(dpint)a[14]*a[21]; tot+=(dpint)a[15]*a[20]; tot+=(dpint)a[16]*a[19]; tot+=(dpint)a[17]*a[18]; tot*=2; t+=tot;  t+=(dpint)v10*p25;  t+=(dpint)v11*p24;  t+=(dpint)v12*p23;  t+=(dpint)v13*p22;  t+=(dpint)v14*p21;  t+=(dpint)v15*p20;  t+=(dpint)v16*p19;  t+=(dpint)v17*p18;  t+=(dpint)v18*p17;  t+=(dpint)v19*p16;  t+=(dpint)v20*p15;  t+=(dpint)v21*p14;  t+=(dpint)v22*p13;  t+=(dpint)v23*p12;  t+=(dpint)v24*p11;  t+=(dpint)v25*p10;  c[9]=((spint)t & mask);  t>>=60;
	tot=(dpint)a[11]*a[25]; tot+=(dpint)a[12]*a[24]; tot+=(dpint)a[13]*a[23]; tot+=(dpint)a[14]*a[22]; tot+=(dpint)a[15]*a[21]; tot+=(dpint)a[16]*a[20]; tot+=(dpint)a[17]*a[19]; tot*=2; tot+=(dpint)a[18]*a[18]; t+=tot;  t+=(dpint)v11*p25;  t+=(dpint)v12*p24;  t+=(dpint)v13*p23;  t+=(dpint)v14*p22;  t+=(dpint)v15*p21;  t+=(dpint)v16*p20;  t+=(dpint)v17*p19;  t+=(dpint)v18*p18;  t+=(dpint)v19*p17;  t+=(dpint)v20*p16;  t+=(dpint)v21*p15;  t+=(dpint)v22*p14;  t+=(dpint)v23*p13;  t+=(dpint)v24*p12;  t+=(dpint)v25*p11;  c[10]=((spint)t & mask);  t>>=60;
	tot=(dpint)a[12]*a[25]; tot+=(dpint)a[13]*a[24]; tot+=(dpint)a[14]*a[23]; tot+=(dpint)a[15]*a[22]; tot+=(dpint)a[16]*a[21]; tot+=(dpint)a[17]*a[20]; tot+=(dpint)a[18]*a[19]; tot*=2; t+=tot;  t+=(dpint)v12*p25;  t+=(dpint)v13*p24;  t+=(dpint)v14*p23;  t+=(dpint)v15*p22;  t+=(dpint)v16*p21;  t+=(dpint)v17*p20;  t+=(dpint)v18*p19;  t+=(dpint)v19*p18;  t+=(dpint)v20*p17;  t+=(dpint)v21*p16;  t+=(dpint)v22*p15;  t+=(dpint)v23*p14;  t+=(dpint)v24*p13;  t+=(dpint)v25*p12;  c[11]=((spint)t & mask);  t>>=60;
	tot=(dpint)a[13]*a[25]; tot+=(dpint)a[14]*a[24]; tot+=(dpint)a[15]*a[23]; tot+=(dpint)a[16]*a[22]; tot+=(dpint)a[17]*a[21]; tot+=(dpint)a[18]*a[20]; tot*=2; tot+=(dpint)a[19]*a[19]; t+=tot;  t+=(dpint)v13*p25;  t+=(dpint)v14*p24;  t+=(dpint)v15*p23;  t+=(dpint)v16*p22;  t+=(dpint)v17*p21;  t+=(dpint)v18*p20;  t+=(dpint)v19*p19;  t+=(dpint)v20*p18;  t+=(dpint)v21*p17;  t+=(dpint)v22*p16;  t+=(dpint)v23*p15;  t+=(dpint)v24*p14;  t+=(dpint)v25*p13;  c[12]=((spint)t & mask);  t>>=60;
	tot=(dpint)a[14]*a[25]; tot+=(dpint)a[15]*a[24]; tot+=(dpint)a[16]*a[23]; tot+=(dpint)a[17]*a[22]; tot+=(dpint)a[18]*a[21]; tot+=(dpint)a[19]*a[20]; tot*=2; t+=tot;  t+=(dpint)v14*p25;  t+=(dpint)v15*p24;  t+=(dpint)v16*p23;  t+=(dpint)v17*p22;  t+=(dpint)v18*p21;  t+=(dpint)v19*p20;  t+=(dpint)v20*p19;  t+=(dpint)v21*p18;  t+=(dpint)v22*p17;  t+=(dpint)v23*p16;  t+=(dpint)v24*p15;  t+=(dpint)v25*p14;  c[13]=((spint)t & mask);  t>>=60;
	tot=(dpint)a[15]*a[25]; tot+=(dpint)a[16]*a[24]; tot+=(dpint)a[17]*a[23]; tot+=(dpint)a[18]*a[22]; tot+=(dpint)a[19]*a[21]; tot*=2; tot+=(dpint)a[20]*a[20]; t+=tot;  t+=(dpint)v15*p25;  t+=(dpint)v16*p24;  t+=(dpint)v17*p23;  t+=(dpint)v18*p22;  t+=(dpint)v19*p21;  t+=(dpint)v20*p20;  t+=(dpint)v21*p19;  t+=(dpint)v22*p18;  t+=(dpint)v23*p17;  t+=(dpint)v24*p16;  t+=(dpint)v25*p15;  c[14]=((spint)t & mask);  t>>=60;
	tot=(dpint)a[16]*a[25]; tot+=(dpint)a[17]*a[24]; tot+=(dpint)a[18]*a[23]; tot+=(dpint)a[19]*a[22]; tot+=(dpint)a[20]*a[21]; tot*=2; t+=tot;  t+=(dpint)v16*p25;  t+=(dpint)v17*p24;  t+=(dpint)v18*p23;  t+=(dpint)v19*p22;  t+=(dpint)v20*p21;  t+=(dpint)v21*p20;  t+=(dpint)v22*p19;  t+=(dpint)v23*p18;  t+=(dpint)v24*p17;  t+=(dpint)v25*p16;  c[15]=((spint)t & mask);  t>>=60;
	tot=(dpint)a[17]*a[25]; tot+=(dpint)a[18]*a[24]; tot+=(dpint)a[19]*a[23]; tot+=(dpint)a[20]*a[22]; tot*=2; tot+=(dpint)a[21]*a[21]; t+=tot;  t+=(dpint)v17*p25;  t+=(dpint)v18*p24;  t+=(dpint)v19*p23;  t+=(dpint)v20*p22;  t+=(dpint)v21*p21;  t+=(dpint)v22*p20;  t+=(dpint)v23*p19;  t+=(dpint)v24*p18;  t+=(dpint)v25*p17;  c[16]=((spint)t & mask);  t>>=60;
	tot=(dpint)a[18]*a[25]; tot+=(dpint)a[19]*a[24]; tot+=(dpint)a[20]*a[23]; tot+=(dpint)a[21]*a[22]; tot*=2; t+=tot;  t+=(dpint)v18*p25;  t+=(dpint)v19*p24;  t+=(dpint)v20*p23;  t+=(dpint)v21*p22;  t+=(dpint)v22*p21;  t+=(dpint)v23*p20;  t+=(dpint)v24*p19;  t+=(dpint)v25*p18;  c[17]=((spint)t & mask);  t>>=60;
	tot=(dpint)a[19]*a[25]; tot+=(dpint)a[20]*a[24]; tot+=(dpint)a[21]*a[23]; tot*=2; tot+=(dpint)a[22]*a[22]; t+=tot;  t+=(dpint)v19*p25;  t+=(dpint)v20*p24;  t+=(dpint)v21*p23;  t+=(dpint)v22*p22;  t+=(dpint)v23*p21;  t+=(dpint)v24*p20;  t+=(dpint)v25*p19;  c[18]=((spint)t & mask);  t>>=60;
	tot=(dpint)a[20]*a[25]; tot+=(dpint)a[21]*a[24]; tot+=(dpint)a[22]*a[23]; tot*=2; t+=tot;  t+=(dpint)v20*p25;  t+=(dpint)v21*p24;  t+=(dpint)v22*p23;  t+=(dpint)v23*p22;  t+=(dpint)v24*p21;  t+=(dpint)v25*p20;  c[19]=((spint)t & mask);  t>>=60;
	tot=(dpint)a[21]*a[25]; tot+=(dpint)a[22]*a[24]; tot*=2; tot+=(dpint)a[23]*a[23]; t+=tot;  t+=(dpint)v21*p25;  t+=(dpint)v22*p24;  t+=(dpint)v23*p23;  t+=(dpint)v24*p22;  t+=(dpint)v25*p21;  c[20]=((spint)t & mask);  t>>=60;
	tot=(dpint)a[22]*a[25]; tot+=(dpint)a[23]*a[24]; tot*=2; t+=tot;  t+=(dpint)v22*p25;  t+=(dpint)v23*p24;  t+=(dpint)v24*p23;  t+=(dpint)v25*p22;  c[21]=((spint)t & mask);  t>>=60;
	tot=(dpint)a[23]*a[25]; tot*=2; tot+=(dpint)a[24]*a[24]; t+=tot;  t+=(dpint)v23*p25;  t+=(dpint)v24*p24;  t+=(dpint)v25*p23;  c[22]=((spint)t & mask);  t>>=60;
	tot=(dpint)a[24]*a[25]; tot*=2; t+=tot;  t+=(dpint)v24*p25;  t+=(dpint)v25*p24;  c[23]=((spint)t & mask);  t>>=60;
	tot=(dpint)a[25]*a[25]; t+=tot;  t+=(dpint)v25*p25;  c[24]=((spint)t & mask);  t>>=60;
	c[25] = (spint)t;
}

//copy
static void modcpy(const spint *a,spint *c) {
	int i;
	for (i=0;i<26;i++) {
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
	spint x[26];
	spint t0[26];
	spint t1[26];
	spint t2[26];
	spint t3[26];
	spint t4[26];
	spint t5[26];
	spint t6[26];
	spint t7[26];
	spint t8[26];
	spint t9[26];
	spint t10[26];
	spint t11[26];
	spint t12[26];
	spint t13[26];
	spint t14[26];
	spint t15[26];
	spint t16[26];
	spint t17[26];
	spint t18[26];
	spint t19[26];
	spint t20[26];
	spint t21[26];
	spint t22[26];
	spint t23[26];
	spint t24[26];
	spint t25[26];
	spint t26[26];
	spint t27[26];
	spint t28[26];
	spint t29[26];
	spint t30[26];
	spint t31[26];
	spint t32[26];
	spint t33[26];
	spint t34[26];
	spint t35[26];
	spint t36[26];
	spint t37[26];
	spint t38[26];
	spint t39[26];
	spint t40[26];
	spint t41[26];
	spint t42[26];
	spint t43[26];
	spint t44[26];
	spint t45[26];
	spint t46[26];
	spint t47[26];
	spint t48[26];
	spint t49[26];
	spint t50[26];
	spint t51[26];
	spint t52[26];
	spint t53[26];
	spint t54[26];
	spint t55[26];
	spint t56[26];
	spint t57[26];
	spint t58[26];
	spint t59[26];
	spint t60[26];
	modcpy(w,x);
	modsqr(x,t0);
	modsqr(t0,t14);
	modmul(t0,t14,z);
	modmul(t0,z,t20);
	modmul(t0,t20,t13);
	modmul(t0,t13,t2);
	modmul(x,t2,t1);
	modmul(x,t1,t46);
	modmul(x,t46,t3);
	modmul(x,t3,t51);
	modmul(t2,t51,t3);
	modmul(x,t3,t11);
	modmul(t2,t3,t52);
	modmul(t0,t52,t12);
	modmul(z,t12,t15);
	modmul(z,t15,t29);
	modmul(t20,t29,t0);
	modmul(t14,t0,t10);
	modmul(t20,t10,t8);
	modmul(t20,t8,t17);
	modmul(t14,t17,t7);
	modmul(z,t7,t16);
	modmul(t3,t7,t9);
	modmul(t2,t9,t24);
	modmul(t29,t16,t6);
	modmul(t46,t6,t34);
	modmul(t13,t34,t56);
	modmul(x,t56,t33);
	modmul(t20,t56,t31);
	modmul(t12,t34,t42);
	modmul(t29,t31,t41);
	modmul(z,t41,t19);
	modmul(t14,t19,t50);
	modmul(t3,t19,t4);
	modmul(t12,t50,z);
	modmul(t12,z,t5);
	modmul(t46,t5,t30);
	modmul(t16,t30,t43);
	modmul(t10,t43,t2);
	modmul(t16,t43,t16);
	modmul(t3,t16,t40);
	modmul(t3,t40,t32);
	modmul(t10,t40,t21);
	modmul(t7,t40,t48);
	modmul(t13,t48,t35);
	modmul(t50,t43,t28);
	modmul(t0,t48,t3);
	modmul(t52,t3,t27);
	modmul(t8,t27,t22);
	modmul(t17,t22,t47);
	modmul(t50,t28,t54);
	modmul(t14,t54,t17);
	modmul(t1,t17,t18);
	modmul(t30,t28,t1);
	modmul(t20,t1,t39);
	modmul(t12,t39,t20);
	modmul(t56,t17,t12);
	modmul(t19,t47,t45);
	modmul(t14,t45,t14);
	modmul(t10,t12,t10);
	modmul(t15,t10,t26);
	modmul(t8,t26,t8);
	modmul(t31,t10,t49);
	modmul(t11,t49,t11);
	modmul(t6,t8,t25);
	modmul(t13,t25,t38);
	modmul(t5,t38,t15);
	modmul(t0,t15,t5);
	modmul(t6,t5,t6);
	modmul(t27,t8,t13);
	modmul(t12,t45,t44);
	modsqr(t14,t36);
	modmul(t54,t11,t55);
	modmul(t28,t5,t23);
	modmul(t2,t23,t2);
	modmul(t19,t2,t19);
	modmul(t34,t19,t37);
	modmul(t33,t37,t33);
	modmul(t29,t33,t29);
	modmul(t38,t36,t34);
	modmul(t0,t34,t0);
	modmul(t11,t0,t11);
	modmul(t49,t11,t49);
	modmul(t25,t49,t53);
	modmul(t9,t53,t25);
	modmul(t8,t25,t9);
	modmul(t46,t9,t8);
	modmul(t39,t8,t39);
	modmul(t38,t39,t59);
	modmul(t12,t59,t12);
	modmul(t17,t12,t17);
	modmul(t35,t17,t38);
	modmul(t10,t38,t10);
	modmul(t47,t10,t47);
	modmul(t7,t47,t7);
	modmul(t35,t7,t35);
	modmul(t46,t35,t46);
	modmul(t22,t46,t22);
	modmul(t6,t22,t6);
	modmul(t40,t6,t40);
	modmul(t56,t40,t58);
	modmul(t52,t58,t57);
	modmul(t20,t57,t56);
	modmul(t26,t56,t26);
	modmul(t0,t26,t0);
	modmul(t2,t0,t2);
	modmul(t21,t2,t21);
	modmul(t34,t21,t34);
	modmul(t50,t34,t52);
	modmul(t42,t52,t42);
	modmul(t48,t42,t60);
	modmul(t45,t60,t45);
	modmul(t4,t45,t4);
	modmul(t31,t4,t31);
	modmul(t32,t31,t32);
	modmul(t23,t32,t23);
	modmul(t36,t23,t36);
	modmul(t3,t36,t3);
	modmul(t41,t3,t48);
	modmul(t5,t48,t5);
	modmul(t41,t5,t41);
	modmul(t28,t41,t28);
	modmul(t30,t28,t50);
	modmul(t20,t50,t20);
	modmul(t27,t20,t27);
	modmul(t19,t27,t30);
	modmul(t15,t30,t15);
	modmul(t16,t15,t19);
	modmul(t16,t19,t16);
	modmul(t14,t16,t14);
	modmul(t44,t14,t44);
	modmul(t1,t44,t1);
	modmul(t54,t1,t54);
	modmul(t37,t54,t37);
	modmul(t24,t37,t24);
	modmul(t43,t24,t43);
	modmul(t13,t43,t13);
	modmul(t51,t13,t51);
	modmul(z,t51,z);
	modnsqr(t60,14);
	modmul(t59,t60,t59);
	modnsqr(t59,20);
	modmul(t58,t59,t58);
	modnsqr(t58,18);
	modmul(t57,t58,t57);
	modnsqr(t57,16);
	modmul(t56,t57,t56);
	modnsqr(t56,13);
	modmul(t55,t56,t55);
	modnsqr(t55,21);
	modmul(t54,t55,t54);
	modnsqr(t54,13);
	modmul(t53,t54,t53);
	modnsqr(t53,19);
	modmul(t52,t53,t52);
	modnsqr(t52,17);
	modmul(t51,t52,t51);
	modnsqr(t51,16);
	modmul(t50,t51,t50);
	modnsqr(t50,13);
	modmul(t49,t50,t49);
	modnsqr(t49,19);
	modmul(t48,t49,t48);
	modnsqr(t48,15);
	modmul(t47,t48,t47);
	modnsqr(t47,17);
	modmul(t46,t47,t46);
	modnsqr(t46,18);
	modmul(t45,t46,t45);
	modnsqr(t45,16);
	modmul(t44,t45,t44);
	modnsqr(t44,16);
	modmul(t43,t44,t43);
	modnsqr(t43,16);
	modmul(t42,t43,t42);
	modnsqr(t42,16);
	modmul(t41,t42,t41);
	modnsqr(t41,18);
	modmul(t40,t41,t40);
	modnsqr(t40,15);
	modmul(t39,t40,t39);
	modnsqr(t39,17);
	modmul(t38,t39,t38);
	modnsqr(t38,19);
	modmul(t37,t38,t37);
	modnsqr(t37,16);
	modmul(t36,t37,t36);
	modnsqr(t36,16);
	modmul(t35,t36,t35);
	modnsqr(t35,20);
	modmul(t34,t35,t34);
	modnsqr(t34,13);
	modmul(t33,t34,t33);
	modnsqr(t33,22);
	modmul(t32,t33,t32);
	modnsqr(t32,17);
	modmul(t31,t32,t31);
	modnsqr(t31,17);
	modmul(t30,t31,t30);
	modnsqr(t30,18);
	modmul(t29,t30,t29);
	modnsqr(t29,21);
	modmul(t28,t29,t28);
	modnsqr(t28,16);
	modmul(t27,t28,t27);
	modnsqr(t27,15);
	modmul(t26,t27,t26);
	modnsqr(t26,14);
	modmul(t25,t26,t25);
	modnsqr(t25,19);
	modmul(t24,t25,t24);
	modnsqr(t24,16);
	modmul(t23,t24,t23);
	modnsqr(t23,15);
	modmul(t22,t23,t22);
	modnsqr(t22,16);
	modmul(t21,t22,t21);
	modnsqr(t21,17);
	modmul(t20,t21,t20);
	modnsqr(t20,16);
	modmul(t19,t20,t19);
	modnsqr(t19,12);
	modmul(t18,t19,t18);
	modnsqr(t18,20);
	modmul(t17,t18,t17);
	modnsqr(t17,18);
	modmul(t16,t17,t16);
	modnsqr(t16,16);
	modmul(t15,t16,t15);
	modnsqr(t15,17);
	modmul(t14,t15,t14);
	modnsqr(t14,16);
	modmul(t13,t14,t13);
	modnsqr(t13,16);
	modmul(t12,t13,t12);
	modnsqr(t12,16);
	modmul(t11,t12,t11);
	modnsqr(t11,17);
	modmul(t10,t11,t10);
	modnsqr(t10,16);
	modmul(t9,t10,t9);
	modnsqr(t9,16);
	modmul(t8,t9,t8);
	modnsqr(t8,19);
	modmul(t7,t8,t7);
	modnsqr(t7,16);
	modmul(t6,t7,t6);
	modnsqr(t6,20);
	modmul(t5,t6,t5);
	modnsqr(t5,16);
	modmul(t4,t5,t4);
	modnsqr(t4,17);
	modmul(t3,t4,t3);
	modnsqr(t3,16);
	modmul(t2,t3,t2);
	modnsqr(t2,17);
	modmul(t1,t2,t1);
	modnsqr(t1,16);
	modmul(t0,t1,t0);
	modnsqr(t0,17);
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
	spint s[26];
	spint t[26];
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
	const spint c[26]={0x4f92fe565ea796eu,0xaca1ca2cc47a010u,0x3933b4e31e7b568u,0xa13e586c3e76376u,0x83021f6332975ceu,0xcade63497b282a5u,0xa5c8e6d8720657cu,0xd2d91b7ad9425bfu,0xf40c1806be4e818u,0xaebf0a7e1141a89u,0x4e2770000160b49u,0x7c0d71002fb49e6u,0x8e63983e2615au,0x804e54ed445ee7eu,0x6a16ab22ce2121cu,0x9700316e3068bc1u,0x78a4f132cd88963u,0x4f01a33e7b32b93u,0x378afc74511ea13u,0x50d0ecf61df1e30u,0x5eeb63dcf053a35u,0x454208e5962e689u,0x7b8ac1ef686e6cbu,0xf8df798dd6ff7eeu,0x66c7874a1e1b757u,0x2cb3659cu};
	modmul(m,c,n);
}

//Convert n back to normal form, m=redc(n) 
static void redc(const spint *n,spint *m) {
	int i;
	spint c[26];
	c[0]=1;
	for (i=1;i<26;i++) {
		c[i]=0;
	}
	modmul(n,c,m);
	(void)modfsb(m);
}

//is unity?
static int modis1(const spint *a) {
	int i;
	spint c[26];
	spint c0;
	spint d=0;
	redc(a,c);
	for (i=1;i<26;i++) {
		d|=c[i];
	}
	c0=(spint)c[0];
	return ((spint)1 & ((d-(spint)1)>>60u) & (((c0^(spint)1)-(spint)1)>>60u));
}

//is zero?
static int modis0(const spint *a) {
	int i;
	spint c[26];
	spint d=0;
	redc(a,c);
	for (i=0;i<26;i++) {
		d|=c[i];
	}
	return ((spint)1 & ((d-(spint)1)>>60u));
}

//set to zero
static void modzer(spint *a) {
	int i;
	for (i=0;i<26;i++) {
		a[i]=0;
	}
}

//set to one
static void modone(spint *a) {
	int i;
	a[0]=1;
	for (i=1;i<26;i++) {
		a[i]=0;
	}
	nres(a,a);
}

//set to integer
static void modint(int x,spint *a) {
	int i;
	a[0]=(spint)x;
	for (i=1;i<26;i++) {
		a[i]=0;
	}
	nres(a,a);
}

// Modular multiplication by an integer, c=a*b mod 2p
// uses special method for trinomials, otherwise Barrett-Dhem reduction
static void modmli(const spint *a,int b,spint *c) {
	spint p8=0xf7b456c00000000u;
	spint p9=0xb1df2a74f745f71u;
	spint p10=0x530814e9c3615eau;
	spint p11=0xa281e3cd1244524u;
	spint p12=0x3afdae93fda6645u;
	spint p13=0xcb3a5035c534b5fu;
	spint p14=0xf8cd6ed92b85bd0u;
	spint p15=0xb3e2fa38f5419bau;
	spint p16=0xf81c420b2dfbb3fu;
	spint p17=0xf58123de8fab63eu;
	spint p18=0x3a493432f085476u;
	spint p19=0x821a8511c268f4cu;
	spint p20=0xf3ede30e07607a2u;
	spint p21=0xc051219e91bdfbfu;
	spint p22=0xf71da19e514541bu;
	spint p23=0xe0e783f6a886397u;
	spint p24=0x50ed1445554f51cu;
	spint p25=0x22606deb0u;
	spint mask=((spint)1<<60u)-(spint)1;
	dpint t=0;
	spint q,h,r=0x1dc9a29cc5f1940a;
	t+=(dpint)a[0]*(dpint)b; c[0]=(spint)t & mask; t=t>>60u;
	t+=(dpint)a[1]*(dpint)b; c[1]=(spint)t & mask; t=t>>60u;
	t+=(dpint)a[2]*(dpint)b; c[2]=(spint)t & mask; t=t>>60u;
	t+=(dpint)a[3]*(dpint)b; c[3]=(spint)t & mask; t=t>>60u;
	t+=(dpint)a[4]*(dpint)b; c[4]=(spint)t & mask; t=t>>60u;
	t+=(dpint)a[5]*(dpint)b; c[5]=(spint)t & mask; t=t>>60u;
	t+=(dpint)a[6]*(dpint)b; c[6]=(spint)t & mask; t=t>>60u;
	t+=(dpint)a[7]*(dpint)b; c[7]=(spint)t & mask; t=t>>60u;
	t+=(dpint)a[8]*(dpint)b; c[8]=(spint)t & mask; t=t>>60u;
	t+=(dpint)a[9]*(dpint)b; c[9]=(spint)t & mask; t=t>>60u;
	t+=(dpint)a[10]*(dpint)b; c[10]=(spint)t & mask; t=t>>60u;
	t+=(dpint)a[11]*(dpint)b; c[11]=(spint)t & mask; t=t>>60u;
	t+=(dpint)a[12]*(dpint)b; c[12]=(spint)t & mask; t=t>>60u;
	t+=(dpint)a[13]*(dpint)b; c[13]=(spint)t & mask; t=t>>60u;
	t+=(dpint)a[14]*(dpint)b; c[14]=(spint)t & mask; t=t>>60u;
	t+=(dpint)a[15]*(dpint)b; c[15]=(spint)t & mask; t=t>>60u;
	t+=(dpint)a[16]*(dpint)b; c[16]=(spint)t & mask; t=t>>60u;
	t+=(dpint)a[17]*(dpint)b; c[17]=(spint)t & mask; t=t>>60u;
	t+=(dpint)a[18]*(dpint)b; c[18]=(spint)t & mask; t=t>>60u;
	t+=(dpint)a[19]*(dpint)b; c[19]=(spint)t & mask; t=t>>60u;
	t+=(dpint)a[20]*(dpint)b; c[20]=(spint)t & mask; t=t>>60u;
	t+=(dpint)a[21]*(dpint)b; c[21]=(spint)t & mask; t=t>>60u;
	t+=(dpint)a[22]*(dpint)b; c[22]=(spint)t & mask; t=t>>60u;
	t+=(dpint)a[23]*(dpint)b; c[23]=(spint)t & mask; t=t>>60u;
	t+=(dpint)a[24]*(dpint)b; c[24]=(spint)t & mask; t=t>>60u;
	t+=(dpint)a[25]*(dpint)b; c[25]=(spint)t;
	
//Barrett-Dhem reduction
	h = (spint)(t>>30u);
	q=(spint)(((dpint)h*(dpint)r)>>64u);
	c[0]+=q;
	t=(dpint)q*(dpint)p8; c[8]-=(spint)t&mask; c[9]-=(spint)(t>>60u);
	t=(dpint)q*(dpint)p9; c[9]-=(spint)t&mask; c[10]-=(spint)(t>>60u);
	t=(dpint)q*(dpint)p10; c[10]-=(spint)t&mask; c[11]-=(spint)(t>>60u);
	t=(dpint)q*(dpint)p11; c[11]-=(spint)t&mask; c[12]-=(spint)(t>>60u);
	t=(dpint)q*(dpint)p12; c[12]-=(spint)t&mask; c[13]-=(spint)(t>>60u);
	t=(dpint)q*(dpint)p13; c[13]-=(spint)t&mask; c[14]-=(spint)(t>>60u);
	t=(dpint)q*(dpint)p14; c[14]-=(spint)t&mask; c[15]-=(spint)(t>>60u);
	t=(dpint)q*(dpint)p15; c[15]-=(spint)t&mask; c[16]-=(spint)(t>>60u);
	t=(dpint)q*(dpint)p16; c[16]-=(spint)t&mask; c[17]-=(spint)(t>>60u);
	t=(dpint)q*(dpint)p17; c[17]-=(spint)t&mask; c[18]-=(spint)(t>>60u);
	t=(dpint)q*(dpint)p18; c[18]-=(spint)t&mask; c[19]-=(spint)(t>>60u);
	t=(dpint)q*(dpint)p19; c[19]-=(spint)t&mask; c[20]-=(spint)(t>>60u);
	t=(dpint)q*(dpint)p20; c[20]-=(spint)t&mask; c[21]-=(spint)(t>>60u);
	t=(dpint)q*(dpint)p21; c[21]-=(spint)t&mask; c[22]-=(spint)(t>>60u);
	t=(dpint)q*(dpint)p22; c[22]-=(spint)t&mask; c[23]-=(spint)(t>>60u);
	t=(dpint)q*(dpint)p23; c[23]-=(spint)t&mask; c[24]-=(spint)(t>>60u);
	t=(dpint)q*(dpint)p24; c[24]-=(spint)t&mask; c[25]-=(spint)(t>>60u);
	c[25]-=q*p25;
	(void)prop(c);
}

//Test for quadratic residue 
static int modqr(const spint *h,const spint *x) {
	spint r[26];
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
	for (i=0;i<26;i++) {
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
	for (i=0;i<26;i++) {
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
	spint s[26];
	spint y[26];
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
	a[25]=((a[25]<<n)) + (a[24]>>(60u-n));
	for (i=24;i>0;i--) {
		a[i]=((a[i]<<n)&(spint)0xfffffffffffffff) + (a[i-1]>>(60u-n));
	}
	a[0]=(a[0]<<n)&(spint)0xfffffffffffffff;
}

//shift right by less than a word. Return shifted out part
static int modshr(unsigned int n,spint *a) {
	int i;
	spint r=a[0]&(((spint)1<<n)-(spint)1);
	for (i=0;i<25;i++) {
		a[i]=(a[i]>>n) + ((a[i+1]<<(60u-n))&(spint)0xfffffffffffffff);
	}
	a[25]=a[25]>>n;
	return r;
}

//divide by 2. Shift right 1 bit (or add p and shift right one bit)
static void modhaf(spint *n) {
	int lsb;
	spint t[26];
	(void)prop(n);
	modcpy(n,t);
	lsb=modshr(1,t);
	n[0]-=(spint)1;
	n[8]+=((spint)0xf7b456c00000000u);
	n[9]+=((spint)0xb1df2a74f745f71u);
	n[10]+=((spint)0x530814e9c3615eau);
	n[11]+=((spint)0xa281e3cd1244524u);
	n[12]+=((spint)0x3afdae93fda6645u);
	n[13]+=((spint)0xcb3a5035c534b5fu);
	n[14]+=((spint)0xf8cd6ed92b85bd0u);
	n[15]+=((spint)0xb3e2fa38f5419bau);
	n[16]+=((spint)0xf81c420b2dfbb3fu);
	n[17]+=((spint)0xf58123de8fab63eu);
	n[18]+=((spint)0x3a493432f085476u);
	n[19]+=((spint)0x821a8511c268f4cu);
	n[20]+=((spint)0xf3ede30e07607a2u);
	n[21]+=((spint)0xc051219e91bdfbfu);
	n[22]+=((spint)0xf71da19e514541bu);
	n[23]+=((spint)0xe0e783f6a886397u);
	n[24]+=((spint)0x50ed1445554f51cu);
	n[25]+=((spint)0x22606deb0u);
	(void)prop(n);
	modshr(1,n);
	modcmv(1-lsb,t,n);
}

//set a= 2^r
static void mod2r(unsigned int r,spint *a) {
	unsigned int n=r/60u;
	unsigned int m=r%60u;
	modzer(a);
	if (r>=192*8) return;
	a[n]=1; a[n]<<=m;
nres(a,a);
}

//export to byte array
static void modexp(const spint *a,char *b) {
	int i;
	spint c[26];
	redc(a,c);
	for (i=191;i>=0;i--) {
		b[i]=c[0]&(spint)0xff;
		(void)modshr(8,c);
	}
}

//import from byte array
//returns 1 if in range, else 0
static int modimp(const char *b, spint *a) {
	int i,res;
	for (i=0;i<26;i++) {
		a[i]=0;
	}
	for (i=0;i<192;i++) {
		modshl(8,a);
		a[0]+=(spint)(unsigned char)b[i];
	}
	res=(int)modfsb(a);
	nres(a,a);
	return res;
}

//determine sign
static int modsign(const spint *a) {
	spint c[26];
	redc(a,c);
	return c[0]%2;
}

//return true if equal
static int modcmp(const spint *a,const spint *b) {
	spint c[26],d[26];
	int i,eq=1;
	redc(a,c);
	redc(b,d);
	for (i=0;i<26;i++) {
		eq&=(((c[i]^d[i])-1)>>60)&1;
	}
	return eq;
}

