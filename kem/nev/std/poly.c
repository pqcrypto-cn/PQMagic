#include <stdio.h>
#include <string.h>
#include "poly.h"
#include "ntt.h"
#include "reduce.h"
#include "symmetrics/hashkdf.h"
#include "api.h"

#if PARAM_Q == 641
int16_t NTT_Y[NTT_DIM] = { 29,-29,-21,21,268,-268,248,-248,305,-305,177,-177,122,-122,199,-199,-210,210,-290,290,-84,84,-116,116,-153,153,155,-155,67,-67,62,-62,-31,31,-287,287,244,-244,-243,243,-105,105,-145,145,-42,42,-58,58,-306,306,310,-310,134,-134,124,-124,-168,168,-232,232,61,-61,-221,221 };
#elif PARAM_Q == 1409
int16_t NTT_Y[NTT_DIM] = {-337,337,-152,152,-328,328,-311,311,299,-299,-116,116,-102,102,393,-393,-462,462,-292,292,-111,111,552,-552,389,-389,-297,297,249,-249,-172,172,-672,672,600,-600,479,-479,-478,478,-587,587,-432,432,106,-106,6,-6,563,-563,-553,553,364,-364,-325,325,-349,349,60,-60,-93,93,234,-234};
#elif PARAM_Q == 3329
int16_t NTT_Y[NTT_DIM] = {
	-1103, 1103, 430, -430, 555, -555, 843, -843,
	-1251, 1251, 871, -871, 1550, -1550, 105, -105,
	422, -422, 587, -587, 177, -177, -235, 235,
	-291, 291, -460, 460, 1574, -1574, 1653, -1653,
	-246, 246, 778, -778, 1159, -1159, -147, 147,
	-777, 777, 1483, -1483, -602, 602, 1119, -1119,
	-1590, 1590, 644, -644, -872, 872, 349, -349,
	418, -418, 329, -329, -156, 156, -75, 75,
	817, -817, 1097, -1097, 603, -603, 610, -610,
	1322, -1322, -1285, 1285, -1465, 1465, 384, -384,
	-1215, 1215, -136, 136, 1218, -1218, -1335, 1335,
	-874, 874, 220, -220, -1187, 1187, -1659, 1659,
	-1185, 1185, -1530, 1530, -1278, 1278, 794, -794,
	-1510, 1510, -854, 854, -870, 870, 478, -478,
	-108, 108, -308, 308, 996, -996, 991, -991,
	958, -958, -1460, 1460, 1522, -1522, 1628, -1628
};
#elif PARAM_Q == 769
int16_t NTT_Y[NTT_DIM] = {
	-341, 341, -379, 379, 202, -202, 220, -220,
	236, -236, 21, -21, 212, -212, 71, -71,
	-134, 134, 151, -151, 23, -23, -112, 112,
	-232, 232, 227, -227, -52, 52, -148, 148,
	244, -244, -252, 252, -237, 237, -83, 83,
	-117, 117, -333, 333, -66, 66, -247, 247,
	-292, 292, 352, -352, -145, 145, 238, -238,
	-276, 276, -194, 194, -274, 274, -70, 70,
	209, -209, -115, 115, -99, 99, 14, -14,
	29, -29, 260, -260, -378, 378, -366, 366,
	355, -355, -291, 291, 358, -358, -105, 105,
	167, -167, 357, -357, -241, 241, -331, 331,
	-348, 348, -44, 44, -78, 78, -222, 222,
	-350, 350, -168, 168, -158, 158, 201, -201,
	303, -303, 330, -330, -184, 184, 127, -127,
	318, -318, -278, 278, -353, 353, -354, 354
};
#endif

#if PARAM_Q == 641

/*
 * Addition chain:
 * 1, 2, 3, 4, 7, 8, 16, 32, 39, 71,
 * 142, 284, 568, 639
 *
 * 639 = q - 2
 */
int16_t mont2_inv(int16_t a)
{
    int16_t y0, y1;

    y1 = fqmul(a, a);       /* 2 */
    y0 = fqmul(y1, a);      /* 3 */

    y1 = fqmul(y1, y1);     /* 4 */
    y0 = fqmul(y0, y1);     /* 7 */

    y1 = fqmul(y1, y1);     /* 8 */
    y1 = fqmul(y1, y1);     /* 16 */
    y1 = fqmul(y1, y1);     /* 32 */

    y0 = fqmul(y1, y0);     /* 39 */
    y0 = fqmul(y1, y0);     /* 71 */

    y1 = fqmul(y0, y0);     /* 142 */
    y1 = fqmul(y1, y1);     /* 284 */
    y1 = fqmul(y1, y1);     /* 568 */
    y1 = fqmul(y1, y0);     /* 639 */

    return y1;
}

#elif PARAM_Q == 1409

/*
 * Addition chain:
 * 1, 2, 4, 8, 16, 32, 64, 128,
 * 192, 200, 201, 402, 804, 1206, 1407
 *
 * 1407 = q - 2
 */
int16_t mont2_inv(int16_t a)
{
    int16_t y0, y1, y2, y3, y4, y5, y6, y7, y8, y9, y10, y11, y12, y13;

    y0  = fqmul(a, a);        /* 2 */
    y1  = fqmul(y0, y0);      /* 4 */
    y2  = fqmul(y1, y1);      /* 8 */
    y3  = fqmul(y2, y2);      /* 16 */
    y4  = fqmul(y3, y3);      /* 32 */
    y5  = fqmul(y4, y4);      /* 64 */
    y6  = fqmul(y5, y5);      /* 128 */

    y7  = fqmul(y5, y6);      /* 192 */
    y8  = fqmul(y7, y2);      /* 200 */
    y9  = fqmul(y8, a);       /* 201 */

    y10 = fqmul(y9, y9);      /* 402 */
    y11 = fqmul(y10, y10);    /* 804 */
    y12 = fqmul(y10, y11);    /* 1206 */
    y13 = fqmul(y12, y9);     /* 1407 */

    return y13;
}

#elif PARAM_Q == 3329

/*
 * Addition chain:
 * 1, 2, 4, 8, 16, 32, 64, 128,
 * 144, 145, 273, 418, 836, 1109, 2218, 3327
 *
 * 3327 = q - 2
 */
int16_t mont2_inv(int16_t a)
{
    int16_t y0, y1, y2, y3, y4, y5, y6, y7, y8, y9, y10, y11, y12, y13, y14;

    y0  = fqmul(a, a);        /* 2 */
    y1  = fqmul(y0, y0);      /* 4 */
    y2  = fqmul(y1, y1);      /* 8 */
    y3  = fqmul(y2, y2);      /* 16 */
    y4  = fqmul(y3, y3);      /* 32 */
    y5  = fqmul(y4, y4);      /* 64 */
    y6  = fqmul(y5, y5);      /* 128 */

    y7  = fqmul(y3, y6);      /* 144 */
    y8  = fqmul(y7, a);       /* 145 */
    y9  = fqmul(y8, y6);      /* 273 */
    y10 = fqmul(y9, y8);      /* 418 */
    y11 = fqmul(y10, y10);    /* 836 */
    y12 = fqmul(y11, y9);     /* 1109 */
    y13 = fqmul(y12, y12);    /* 2218 */
    y14 = fqmul(y13, y12);    /* 3327 */

    return y14;
}
#elif PARAM_Q == 769

/*
 * Addition chain:
 * 1, 2, 4, 8, 16, 32, 64, 72, 73,
 * 137, 274, 347, 694, 767
 *
 * 767 = q - 2
 *
 */
int16_t mont2_inv(int16_t a)
{
	int16_t y0, y1;

	y0 = fqmul(a, a);       /* 2 */
	y0 = fqmul(y0, y0);     /* 4 */
	y0 = fqmul(y0, y0);     /* 8 */

	y1 = fqmul(y0, y0);     /* 16 */
	y1 = fqmul(y1, y1);     /* 32 */
	y1 = fqmul(y1, y1);     /* 64 */

	y0 = fqmul(y1, y0);     /* 72*/
	y0 = fqmul(y0, a);      /* 73*/

	y1 = fqmul(y0, y1);     /* 137 */
	y1 = fqmul(y1, y1);     /* 274 */
	y1 = fqmul(y1, y0);     /* 347 */
	y1 = fqmul(y1, y1);     /* 694 */
	y1 = fqmul(y1, y0);     /* 767 */

	return y1;
}
#endif

static inline int batch_mont2_inv(int16_t *r, const int16_t *a)
{
	int i;
	int16_t acc, tmp;

	r[0] = a[0];
	for (i = 1; i < NTT_DIM; i++)
		r[i] = fqmul(r[i - 1], a[i]);

	if (r[NTT_DIM - 1] == 0)
		return 0;

	acc = mont2_inv(r[NTT_DIM - 1]);

	for (i = NTT_DIM - 1; i > 0; i--)
	{
		tmp = fqmul(acc, r[i - 1]);
		acc = fqmul(acc, a[i]);
		r[i] = tmp;
	}

	r[0] = acc;
	return 1;
}
void poly_caddq(poly *r)
{
	int i;
	for (i = 0; i < PARAM_N; i++)
		r->coeffs[i] = caddq(r->coeffs[i]);
}
void poly_reduce(poly *r)
{
	int i;
	for (i = 0; i < PARAM_N; i++)
		r->coeffs[i] = barrett_reduce(r->coeffs[i]);
}
void poly_rotv(poly* r, poly* a)
{
	int i, j;
	int16_t t;
	for (i = 0; i < PARAM_N / NTT_DIM; i++)
	{
		for (j = 0; j < SEED_BYTES * 8 * NTT_DIM / PARAM_N; j++)
			r->coeffs[i * NTT_DIM + j] = a->coeffs[i * NTT_DIM + NTT_DIM - SEED_BYTES * 8 * NTT_DIM / PARAM_N + j];
		for (j = 0; j < NTT_DIM - SEED_BYTES * 8 * NTT_DIM / PARAM_N; j++)
			r->coeffs[i * NTT_DIM + SEED_BYTES * 8 * NTT_DIM / PARAM_N + j] = -a->coeffs[i * NTT_DIM + j];
	}
}

void poly_add(poly *r, const poly *a, const poly *b)
{
	int i;
	for (i = 0; i < PARAM_N; i++)
		r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
}
void poly_sub(poly *r, const poly *a, const poly *b)
{
	int i;
	for (i = 0; i < PARAM_N; i++)
		r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
}
void poly_ntt(poly *r)
{
	int i = 0;
	for (i = 0; i < PARAM_N / NTT_DIM; i++)
		ntt(&r->coeffs[i*NTT_DIM]);
}
void poly_invntt(poly *r)
{
	int i = 0;
	for (i = 0; i < PARAM_N / NTT_DIM; i++)
		invntt(&r->coeffs[i*NTT_DIM]);
}



static inline void mont_mul4(int16_t* r, const int16_t* a, const int16_t* b)//multiplication for degree 3 polynomial/4 coefficients
{
	int32_t t[14];
	int i, j;
	for (i = 0; i < NTT_DIM; i++)
	{
		for (j = 0; j < 4; j++)
			t[j] = a[j * NTT_DIM + i];//a0,a1,a2,a3
		for (j = 0; j < 4; j++)
			t[4 + j] = b[j * NTT_DIM + i];//b0,b1,b2,b3

		t[8] = montgomery_reduce(t[0] * t[4]);
		t[9] = montgomery_reduce((t[0] + t[1]) * (t[4] + t[5]));
		t[10] = montgomery_reduce(t[1] * t[5]);
		t[9] = t[9] - t[8] - t[10];

		t[11] = montgomery_reduce(t[2] * t[6]);
		t[12] = montgomery_reduce((t[2] + t[3]) * (t[6] + t[7]));
		t[13] = montgomery_reduce(t[3] * t[7]);
		t[12] = t[12] - t[11] - t[13];

		t[0] = t[0] + t[2];
		t[1] = t[1] + t[3];
		t[2] = t[4] + t[6];
		t[3] = t[5] + t[7];

		t[4] = montgomery_reduce(t[0] * t[2]);
		t[5] = montgomery_reduce((t[0] + t[1]) * (t[2] + t[3]));
		t[6] = montgomery_reduce(t[1] * t[3]);
		t[5] = t[5] - t[4] - t[6];

		t[4] = t[4] - t[8] - t[11];
		t[5] = t[5] - t[9] - t[12];
		t[6] = t[6] - t[10] - t[13];


		r[i] = t[8];
		r[NTT_DIM + i] = t[9];
		r[2 * NTT_DIM + i] = t[4] + t[10];
		r[3 * NTT_DIM + i] = t[5];
		r[4 * NTT_DIM + i] = t[6] + t[11];
		r[5 * NTT_DIM + i] = t[12];
		r[6 * NTT_DIM + i] = t[13];
	}
}
static inline void mont_double_mul4(int16_t* r, const int16_t* a, const int16_t* b)//multiplication for degree 3 polynomial/4 coefficients
{
	int32_t t[14];
	int i, j;
	for (i = 0; i < NTT_DIM; i++)
	{
		for (j = 0; j < 4; j++)
			t[j] = 2 * a[j * NTT_DIM + i];//a0,a1,a2,a3
		for (j = 0; j < 4; j++)
			t[4 + j] = b[j * NTT_DIM + i];//b0,b1,b2,b3

		t[8] = montgomery_reduce(t[0] * t[4]);
		t[9] = montgomery_reduce((t[0] + t[1]) * (t[4] + t[5]));
		t[10] = montgomery_reduce(t[1] * t[5]);
		t[9] = t[9] - t[8] - t[10];

		t[11] = montgomery_reduce(t[2] * t[6]);
		t[12] = montgomery_reduce((t[2] + t[3]) * (t[6] + t[7]));
		t[13] = montgomery_reduce(t[3] * t[7]);
		t[12] = t[12] - t[11] - t[13];

		t[0] = t[0] + t[2];
		t[1] = t[1] + t[3];
		t[2] = t[4] + t[6];
		t[3] = t[5] + t[7];

		t[4] = montgomery_reduce(t[0] * t[2]);
		t[5] = montgomery_reduce((t[0] + t[1]) * (t[2] + t[3]));
		t[6] = montgomery_reduce(t[1] * t[3]);
		t[5] = t[5] - t[4] - t[6];

		t[4] = t[4] - t[8] - t[11];
		t[5] = t[5] - t[9] - t[12];
		t[6] = t[6] - t[10] - t[13];


		r[i] = t[8];
		r[NTT_DIM + i] = t[9];
		r[2 * NTT_DIM + i] = t[4] + t[10];
		r[3 * NTT_DIM + i] = t[5];
		r[4 * NTT_DIM + i] = t[6] + t[11];
		r[5 * NTT_DIM + i] = t[12];
		r[6 * NTT_DIM + i] = t[13];
	}
}
static inline void mont_mul8(int16_t* r, const int16_t* a, const int16_t* b)
{
	int16_t t1[7 * NTT_DIM], t2[7 * NTT_DIM];
	int i;
	for (i = 0; i < 4 * NTT_DIM; i++)
	{
		t1[i] = a[i] + a[4 * NTT_DIM + i];
		t2[i] = b[i] + b[4 * NTT_DIM + i];
	}
	mont_mul4(t1, t1, t2);
	mont_mul4(&r[8 * NTT_DIM], &a[4 * NTT_DIM], &b[4 * NTT_DIM]);
	mont_mul4(r, a, b);

	for (i = 0; i < NTT_DIM; i++)
		r[7 * NTT_DIM + i] = barrett_reduce(t1[3 * NTT_DIM + i] - r[3 * NTT_DIM + i] - r[11 * NTT_DIM + i]);
	for (i = 0; i < 3 * NTT_DIM; i++)
	{
		t1[i] = barrett_reduce(r[4 * NTT_DIM + i] + t1[i] - r[i] - r[8 * NTT_DIM + i]);
		r[8 * NTT_DIM + i] = barrett_reduce(t1[4 * NTT_DIM + i] - r[4 * NTT_DIM + i] - r[12 * NTT_DIM + i] + r[8 * NTT_DIM + i]);
		r[4 * NTT_DIM + i] = t1[i];
	}
}
static inline void mont_mul16(int16_t* r, const int16_t* a, const int16_t* b)
{
	int16_t t1[15 * NTT_DIM], t2[15 * NTT_DIM];
	int i;
	for (i = 0; i < 8 * NTT_DIM; i++)
	{
		t1[i] = a[i] + a[8 * NTT_DIM + i];
		t2[i] = b[i] + b[8 * NTT_DIM + i];
	}
	mont_mul8(t1, t1, t2);
	mont_mul8(&r[16 * NTT_DIM], &a[8 * NTT_DIM], &b[8 * NTT_DIM]);//t2
	mont_mul8(r, a, b);//t0


	for (i = 0; i < NTT_DIM; i++)
		r[15 * NTT_DIM + i] = t1[7 * NTT_DIM + i] - r[7 * NTT_DIM + i] - r[23 * NTT_DIM + i];
	for (i = 0; i < 7 * NTT_DIM; i++)
	{
		t1[i] = (r[8 * NTT_DIM + i] + t1[i] - r[i] - r[16 * NTT_DIM + i]);
		r[16 * NTT_DIM + i] = t1[8 * NTT_DIM + i] - r[8 * NTT_DIM + i] - r[24 * NTT_DIM + i] + r[16 * NTT_DIM + i];
		r[8 * NTT_DIM + i] = t1[i];
	}
}
static inline void mont_double_mul8(int16_t* r, const int16_t* a, const int16_t* b)//12 times double?
{
	int16_t t1[7 * NTT_DIM], t2[8 * NTT_DIM],t3[4 * NTT_DIM];
	int i;
	for (i = 0; i < 4 * NTT_DIM; i++)
	{
		t2[i] = 2*a[i];
		t2[4 * NTT_DIM + i] = 2*a[4 * NTT_DIM + i];
		t1[i] = t2[i] + t2[4 * NTT_DIM + i];
		t3[i] = b[i] + b[4 * NTT_DIM + i];
	}

	mont_mul4(t1, t1, t3);
	mont_mul4(&r[8 * NTT_DIM], &t2[4 * NTT_DIM], &b[4 * NTT_DIM]);
	mont_mul4(r, t2, b);

	for (i = 0; i < NTT_DIM; i++)
		r[7 * NTT_DIM + i] = barrett_reduce(t1[3 * NTT_DIM + i] - r[3 * NTT_DIM + i] - r[11 * NTT_DIM + i]);
	for (i = 0; i < 3 * NTT_DIM; i++)
	{
		t1[i] = barrett_reduce(r[4 * NTT_DIM + i] + t1[i] - r[i] - r[8 * NTT_DIM + i]);
		r[8 * NTT_DIM + i] = barrett_reduce(t1[4 * NTT_DIM + i] - r[4 * NTT_DIM + i] - r[12 * NTT_DIM + i] + r[8 * NTT_DIM + i]);
		r[4 * NTT_DIM + i] = t1[i];
	}
}
static inline void mont_square4(int16_t* r, const int16_t* a)//multiplication for degree 3 polynomial/4 coefficients
{
	int32_t t[12];
	int i, j;
	for (i = 0; i < NTT_DIM; i++)
	{
		for (j = 0; j < 4; j++)
			t[j] = a[j * NTT_DIM + i];//a0,a1,a2,a3

		t[4] = montgomery_reduce(t[0] * t[0]);
		t[6] = montgomery_reduce(t[1] * t[1]);
		t[0] = t[0] << 1;
		t[5] = montgomery_reduce(t[0] * t[1]);
		t[1] = t[1] << 1;

		t[9] = montgomery_reduce(t[0] * t[2]);
		t[7] = montgomery_reduce((t[0] + t[1]) * (t[2] + t[3]));
		t[8] = montgomery_reduce(t[1] * t[3]);
		t[7] = t[7] - t[8] - t[9];
		t[6] = t[6] + t[9];

		t[11] = montgomery_reduce(t[2] * t[2]);
		t[9] = montgomery_reduce(2 * t[2] * t[3]);
		t[10] = montgomery_reduce(t[3] * t[3]);
		t[8] = t[8] + t[11];//4,5,6,7,8,9,10

		for (j = 0; j < 7; j++)
			r[j * NTT_DIM + i] = t[4 + j];
	}
}
static inline void mont_square8(int16_t* r, const int16_t* a)//multiplication for degree 3 polynomial/4 coefficients
{
	int16_t t1[7 * NTT_DIM];
	int i;

	mont_double_mul4(t1, a, &a[4 * NTT_DIM]);
	mont_square4(&r[8 * NTT_DIM], &a[4 * NTT_DIM]);
	mont_square4(r, a);

	for (i = 0; i < NTT_DIM; i++)
		r[7 * NTT_DIM + i] = barrett_reduce(t1[3 * NTT_DIM + i]);

	for (i = 0; i < 3 * NTT_DIM; i++)
	{
		r[4 * NTT_DIM + i] = barrett_reduce(r[4 * NTT_DIM + i] + t1[i]);
		r[8 * NTT_DIM + i] = barrett_reduce(t1[4 * NTT_DIM + i] + r[8 * NTT_DIM + i]);
	}
}
static inline void mont_square16(int16_t* r, const int16_t* a)//multiplication for degree 3 polynomial/4 coefficients
{
	int16_t t0[15 * NTT_DIM], t1[15 * NTT_DIM], t2[15 * NTT_DIM];
	int i, j;

	mont_square8(t0, a);
	mont_double_mul8(t1, a, &a[8 * NTT_DIM]);
	mont_square8(t2, &a[8 * NTT_DIM]);

	for (i = 0; i < 8 * NTT_DIM; i++)
		r[i] = t0[i];
	for (i = 0; i < 7 * NTT_DIM; i++)
		r[8 * NTT_DIM + i] = t0[8 * NTT_DIM + i] + t1[i];
	for (i = 0; i < NTT_DIM; i++)
		r[15 * NTT_DIM + i] = t1[7 * NTT_DIM + i];
	for (i = 0; i < 7 * NTT_DIM; i++)
		r[16 * NTT_DIM + i] = t1[8 * NTT_DIM + i] + t2[i];
	for (i = 0; i < 8 * NTT_DIM; i++)
		r[23 * NTT_DIM + i] = t2[7 * NTT_DIM + i];
}
static inline int mont2_inverse4(int16_t* r, const int16_t* a)
{
	int32_t t[8];
	int16_t s;
	int16_t a2_0[NTT_DIM];
	int16_t a2_1[NTT_DIM];
	int16_t s_arr[NTT_DIM];
	int16_t s_inv[NTT_DIM];
	int i, j;

	for (i = 0; i < NTT_DIM; i++)
	{
		for (j = 0; j < 4; j++)
			t[j] = a[j * NTT_DIM + i];

		t[4] = montgomery_reduce(2 * t[1] * t[3]);
		t[5] = montgomery_reduce(t[2] * t[2]);
		t[4] = t[5] - t[4];
		t[4] = montgomery_reduce(t[4] * NTT_Y[i]);
		t[5] = montgomery_reduce(t[0] * t[0]);
		t[4] = t[4] + t[5];//a2_0

		t[5] = montgomery_reduce(2 * t[0] * t[2]);
		t[6] = montgomery_reduce(t[1] * t[1]);
		t[5] = t[5] - t[6];
		t[6] = montgomery_reduce(t[3] * t[3]);
		t[6] = montgomery_reduce(t[6] * NTT_Y[i]);
		t[5] = t[5] - t[6];//a2_1

		t[6] = montgomery_reduce(t[4] * t[4]);
		t[7] = montgomery_reduce(t[5] * t[5]);
		t[7] = montgomery_reduce(t[7] * NTT_Y[i]);

		s = t[6] - t[7];//a3_0
		s = barrett_reduce(s);
		s = caddq(s);

		a2_0[i] = (int16_t)t[4];
		a2_1[i] = (int16_t)t[5];
		s_arr[i] = s;
	}

	if (!batch_mont2_inv(s_inv, s_arr))
		return 0;

	for (i = 0; i < NTT_DIM; i++)
	{
		for (j = 0; j < 4; j++)
			t[j] = a[j * NTT_DIM + i];

		t[4] = a2_0[i];
		t[5] = a2_1[i];
		s = s_inv[i];

		t[4] = montgomery_reduce(t[4] * s);//a2'_0
		t[5] = montgomery_reduce(t[5] * s);//a2'_1

		t[6] = montgomery_reduce(t[0] * t[4]);//a1_0 a2'_0
		t[7] = montgomery_reduce(t[1] * t[4]);//a1_1 a2'_0

		t[0] = montgomery_reduce((t[0] + t[2]) * (t[4] - t[5]));
		t[1] = montgomery_reduce((t[1] - t[3]) * (t[4] + t[5]));
		t[2] = montgomery_reduce(t[2] * t[5]);//a1_2 a2'_1
		t[3] = montgomery_reduce(t[3] * t[5]);//a1_3 a2'_1

		t[4] = montgomery_reduce(t[2] * NTT_Y[i]);
		t[5] = montgomery_reduce(t[3] * NTT_Y[i]);

		r[i] = t[6] - t[4];//<= 2*PARAM_Q
		r[NTT_DIM + i] = t[5] - t[7];//<= 2*PARAM_Q
		r[2 * NTT_DIM + i] = t[0] - t[6] + t[2];//<= 2*PARAM_Q
		r[3 * NTT_DIM + i] = t[1] - t[7] + t[3];//<= 2*PARAM_Q
	}

	return 1;
}
static inline int mont2_inverse4_judge(int16_t* r, const int16_t* a)
{
	int32_t t[8];
	int16_t s;
	int i, j;

	for (i = 0; i < NTT_DIM; i++)
	{
		for (j = 0; j < 4; j++)
			t[j] = a[j * NTT_DIM + i];

		t[4] = montgomery_reduce(2 * t[1] * t[3]);
		t[5] = montgomery_reduce(t[2] * t[2]);
		t[4] = t[5] - t[4];
		t[4] = montgomery_reduce(t[4] * NTT_Y[i]);
		t[5] = montgomery_reduce(t[0] * t[0]);
		t[4] = t[4] + t[5];//a2_0

		t[5] = montgomery_reduce(2 * t[0] * t[2]);
		t[6] = montgomery_reduce(t[1] * t[1]);
		t[5] = t[5] - t[6];
		t[6] = montgomery_reduce(t[3] * t[3]);
		t[6] = montgomery_reduce(t[6] * NTT_Y[i]);
		t[5] = t[5] - t[6];//a2_1

		t[6] = montgomery_reduce(t[4] * t[4]);
		t[7] = montgomery_reduce(t[5] * t[5]);
		t[7] = montgomery_reduce(t[7] * NTT_Y[i]);

		s = t[6] - t[7];//a3_0
		s = barrett_reduce(s);
		s = caddq(s);
		if (s == 0) //no inverse
			return 0;
	}
	return 1;
}
static inline int mont2_inverse8(int16_t* r, const int16_t* a)
{
	int16_t t0[4 * NTT_DIM], t1[4 * NTT_DIM];
	int16_t b0[7 * NTT_DIM], b1[7 * NTT_DIM];

	int i, j;
	for (j = 0; j < 4; j++)
	{
		memcpy(&t0[j * NTT_DIM], &a[2 * j * NTT_DIM], NTT_DIM * 2);
		memcpy(&t1[j * NTT_DIM], &a[(2 * j + 1) * NTT_DIM], NTT_DIM * 2);
	}

	mont_square4(b0, t0);
	mont_square4(b1, t1);


	for (j = 0; j < NTT_DIM; j++)
	{
		b0[4 * NTT_DIM + j] = montgomery_reduce(b0[4 * NTT_DIM + j] * NTT_Y[j]);
		b1[3 * NTT_DIM + j] = montgomery_reduce(b1[3 * NTT_DIM + j] * NTT_Y[j]);
		b0[j] = b0[j] + b0[4 * NTT_DIM + j] - b1[3 * NTT_DIM + j];


		b0[5 * NTT_DIM + j] = montgomery_reduce(b0[5 * NTT_DIM + j] * NTT_Y[j]);
		b1[4 * NTT_DIM + j] = montgomery_reduce(b1[4 * NTT_DIM + j] * NTT_Y[j]);
		b0[NTT_DIM + j] = b0[NTT_DIM + j] + b0[5 * NTT_DIM + j] - b1[j] - b1[4 * NTT_DIM + j];

		b0[6 * NTT_DIM + j] = montgomery_reduce(b0[6 * NTT_DIM + j] * NTT_Y[j]);
		b1[5 * NTT_DIM + j] = montgomery_reduce(b1[5 * NTT_DIM + j] * NTT_Y[j]);
		b0[2 * NTT_DIM + j] = b0[2 * NTT_DIM + j] + b0[6 * NTT_DIM + j] - b1[NTT_DIM + j] - b1[5 * NTT_DIM + j];

		b1[6 * NTT_DIM + j] = montgomery_reduce(b1[6 * NTT_DIM + j] * NTT_Y[j]);
		b0[3 * NTT_DIM + j] = b0[3 * NTT_DIM + j] - b1[2 * NTT_DIM + j] - b1[6 * NTT_DIM + j];
	}

	if (!mont2_inverse4(b1, b0))
		return 0;

	mont_mul4(b0, b1, t0);
	mont_mul4(b1, b1, t1);

	for (i = 0; i < 3; i++)
		for (j = 0; j < NTT_DIM; j++)
		{
			b0[(4 + i) * NTT_DIM + j] = montgomery_reduce(b0[(4 + i) * NTT_DIM + j] * NTT_Y[j]);
			b1[(4 + i) * NTT_DIM + j] = montgomery_reduce(b1[(4 + i) * NTT_DIM + j] * NTT_Y[j]);

			r[2 * i * NTT_DIM + j] = b0[i * NTT_DIM + j] + b0[(4 + i) * NTT_DIM + j];
			r[(2 * i + 1) * NTT_DIM + j] = -b1[i * NTT_DIM + j] - b1[(4 + i) * NTT_DIM + j];
		}

	for (i = 3; i < 4; i++)
	{
		memcpy(&r[2 * i * NTT_DIM], &b0[i * NTT_DIM], NTT_DIM * 2);
		for (j = 0; j < NTT_DIM; j++)
			r[(2 * i + 1) * NTT_DIM + j] = -b1[i * NTT_DIM +j];
	}


	return 1;
}
static inline int mont2_inverse8_judge(int16_t* r, const int16_t* a)
{
	int16_t t0[4 * NTT_DIM], t1[4 * NTT_DIM];
	int16_t b0[7 * NTT_DIM], b1[7 * NTT_DIM];

	int i, j;
	for (j = 0; j < 4; j++)
	{
		memcpy(&t0[j * NTT_DIM], &a[2 * j * NTT_DIM], NTT_DIM * 2);
		memcpy(&t1[j * NTT_DIM], &a[(2 * j + 1) * NTT_DIM], NTT_DIM * 2);
	}

	mont_square4(b0, t0);
	mont_square4(b1, t1);


	for (j = 0; j < NTT_DIM; j++)
	{
		b0[4 * NTT_DIM + j] = montgomery_reduce(b0[4 * NTT_DIM + j] * NTT_Y[j]);
		b1[3 * NTT_DIM + j] = montgomery_reduce(b1[3 * NTT_DIM + j] * NTT_Y[j]);
		b0[j] = b0[j] + b0[4 * NTT_DIM + j] - b1[3 * NTT_DIM + j];


		b0[5 * NTT_DIM + j] = montgomery_reduce(b0[5 * NTT_DIM + j] * NTT_Y[j]);
		b1[4 * NTT_DIM + j] = montgomery_reduce(b1[4 * NTT_DIM + j] * NTT_Y[j]);
		b0[NTT_DIM + j] = b0[NTT_DIM + j] + b0[5 * NTT_DIM + j] - b1[j] - b1[4 * NTT_DIM + j];

		b0[6 * NTT_DIM + j] = montgomery_reduce(b0[6 * NTT_DIM + j] * NTT_Y[j]);
		b1[5 * NTT_DIM + j] = montgomery_reduce(b1[5 * NTT_DIM + j] * NTT_Y[j]);
		b0[2 * NTT_DIM + j] = b0[2 * NTT_DIM + j] + b0[6 * NTT_DIM + j] - b1[NTT_DIM + j] - b1[5 * NTT_DIM + j];

		b1[6 * NTT_DIM + j] = montgomery_reduce(b1[6 * NTT_DIM + j] * NTT_Y[j]);
		b0[3 * NTT_DIM + j] = b0[3 * NTT_DIM + j] - b1[2 * NTT_DIM + j] - b1[6 * NTT_DIM + j];
	}

	return mont2_inverse4_judge(b1, b0);
}
static inline int mont2_inverse16(int16_t* r, const int16_t* a) 
{
	int16_t t0[8 * NTT_DIM], t1[8 * NTT_DIM];
	int16_t b0[15 * NTT_DIM], b1[15 * NTT_DIM];
	int i, j;

	for (j = 0; j < 8; j++)
		for (i = 0; i < NTT_DIM; i++)
			t0[j * NTT_DIM + i] = a[2 * j * NTT_DIM + i];
	for (j = 0; j < 8; j++)
		for (i = 0; i < NTT_DIM; i++)
			t1[j * NTT_DIM + i] = a[(2 * j + 1) * NTT_DIM + i];

	mont_square8(b0, t0);
	mont_square8(b1, t1);

	for (i = 8; i < 15; i++)
		for (j = 0; j < NTT_DIM; j++)
			b0[i * NTT_DIM + j] = montgomery_reduce(b0[i * NTT_DIM + j] * NTT_Y[j]);

	for (i = 7; i < 15; i++)
		for (j = 0; j < NTT_DIM; j++)
			b1[i * NTT_DIM + j] = montgomery_reduce(b1[i * NTT_DIM + j] * NTT_Y[j]);

	for (j = 0; j < 7 * NTT_DIM; j++)
		b0[j] = b0[j] + b0[8 * NTT_DIM + j];
	
	for (j = 0; j < 8 * NTT_DIM; j++)
		b0[j] = b0[j] - b1[7 * NTT_DIM + j];

	for (j = 0; j < 7 * NTT_DIM; j++)
		b0[NTT_DIM + j] = b0[NTT_DIM + j] - b1[j];

	if (!mont2_inverse8(b1, b0))
		return 0;

	mont_mul8(b0, b1, t0);
	mont_mul8(b1, b1, t1);

	for (i = 8; i < 15; i++)
		for (j = 0; j < NTT_DIM; j++)
			b0[i * NTT_DIM + j] = montgomery_reduce(b0[i * NTT_DIM + j] * NTT_Y[j]);

	for (i = 8; i < 15; i++)
		for (j = 0; j < NTT_DIM; j++)
			b1[i * NTT_DIM + j] = montgomery_reduce(b1[i * NTT_DIM + j] * NTT_Y[j]);

	for (i = 0; i < 7 * NTT_DIM; i++)
		b0[i] = b0[i] + b0[8 * NTT_DIM + i];

	for (i = 0; i < 7 * NTT_DIM; i++)
		b1[i] = b1[i] + b1[8 * NTT_DIM + i];

	for (i = 0; i < 8; i++)
		for (j = 0; j < NTT_DIM; j++)
		{
			r[2 * i * NTT_DIM + j] = b0[i * NTT_DIM + j];
			r[(2 * i + 1) * NTT_DIM + j] = -b1[i * NTT_DIM + j];
		}
	return 1;
}
static inline int mont2_inverse16_judge(int16_t* r, const int16_t* a)
{
	int16_t t0[8 * NTT_DIM], t1[8 * NTT_DIM];
	int16_t b0[15 * NTT_DIM], b1[15 * NTT_DIM];
	int i, j;

	for (j = 0; j < 8; j++)
		for (i = 0; i < NTT_DIM; i++)
			t0[j * NTT_DIM + i] = a[2 * j * NTT_DIM + i];
	for (j = 0; j < 8; j++)
		for (i = 0; i < NTT_DIM; i++)
			t1[j * NTT_DIM + i] = a[(2 * j + 1) * NTT_DIM + i];

	mont_square8(b0, t0);
	mont_square8(b1, t1);

	for (i = 8; i < 15; i++)
		for (j = 0; j < NTT_DIM; j++)
			b0[i * NTT_DIM + j] = montgomery_reduce(b0[i * NTT_DIM + j] * NTT_Y[j]);

	for (i = 7; i < 15; i++)
		for (j = 0; j < NTT_DIM; j++)
			b1[i * NTT_DIM + j] = montgomery_reduce(b1[i * NTT_DIM + j] * NTT_Y[j]);

	for (j = 0; j < 7 * NTT_DIM; j++)
		b0[j] = b0[j] + b0[8 * NTT_DIM + j];

	for (j = 0; j < 8 * NTT_DIM; j++)
		b0[j] = b0[j] - b1[7 * NTT_DIM + j];

	for (j = 0; j < 7 * NTT_DIM; j++)
		b0[NTT_DIM + j] = b0[NTT_DIM + j] - b1[j];

	return mont2_inverse8_judge(b1, b0);
}
#if PARAM_N/NTT_DIM == 4
void poly_mont_mul(poly* r, const poly* a, const poly* b) {
	int16_t t[7 * NTT_DIM];
	int i, j;

	mont_mul4(t, a->coeffs, b->coeffs);

	for (i = 0; i < 3; i++) {
		for (j = 0; j < NTT_DIM; j++) {
			r->coeffs[i * NTT_DIM + j] =
				t[i * NTT_DIM + j] +
				montgomery_reduce(t[(4 + i) * NTT_DIM + j] * NTT_Y[j]);
		}
	}
	for (j = 0; j < NTT_DIM; j++)
		r->coeffs[3 * NTT_DIM + j] = t[3 * NTT_DIM + j];
}
int poly_mont2_inverse(poly* r, const poly*a) {
	return mont2_inverse4(r->coeffs, a->coeffs);
}
int poly_mont2_inverse_judge(const poly* a) {
	int16_t t[PARAM_N];
	return mont2_inverse4_judge(t, a->coeffs);
}
#elif PARAM_N/NTT_DIM == 8
void poly_mont_mul(poly* r, const poly* a, const poly* b)
{
	int16_t t0[PARAM_N], t1[PARAM_N], t2[PARAM_N];
	int i,j;
	for (i = 0; i < PARAM_N/2; i++)
	{
		t0[i] = a->coeffs[i] + a->coeffs[PARAM_N / 2 + i];
		t1[i] = b->coeffs[i] + b->coeffs[PARAM_N / 2 + i];
	}
	
	mont_mul4(t1,t0,t1);
	mont_mul4(t0, a->coeffs, b->coeffs);
	mont_mul4(t2, &a->coeffs[PARAM_N/2], &b->coeffs[PARAM_N / 2]);

	for (i = 0; i < 7*NTT_DIM; i++)
		t1[i] -= (t0[i] + t2[i]);

	for (i = 0; i < 3 * NTT_DIM; i++)
	{
		t0[4 * NTT_DIM + i] = (t0[4 * NTT_DIM + i] + t1[i]);
		t2[i] = (t1[4 * NTT_DIM + i] + t2[i]);
	}

	for(i=0;i<7;i++)
		for (j = 0; j < NTT_DIM; j++)
			t2[i * NTT_DIM + j] = montgomery_reduce(t2[i * NTT_DIM + j] * NTT_Y[j]);

	for (i = 0; i < 7 * NTT_DIM; i++)
		r->coeffs[i] = t0[i] + t2[i];
	for (i = 0; i < NTT_DIM; i++)
		r->coeffs[7 * NTT_DIM + i] = t1[3 * NTT_DIM + i];
}
int poly_mont2_inverse(poly* r, const poly*a)
{
	int16_t t0[4 * NTT_DIM], t1[4 * NTT_DIM];
	int16_t b0[7 * NTT_DIM], b1[7 * NTT_DIM];

	int i, j;
	for (j = 0; j < 4; j++)
	{
		memcpy(&t0[j * NTT_DIM], &a->coeffs[2 * j * NTT_DIM], NTT_DIM * 2);
		memcpy(&t1[j * NTT_DIM], &a->coeffs[(2 * j + 1) * NTT_DIM], NTT_DIM * 2);
	}

	mont_square4(b0, t0);
	mont_square4(b1, t1);


	for (j = 0; j < NTT_DIM; j++)
	{
		b0[4 * NTT_DIM + j] = montgomery_reduce(b0[4 * NTT_DIM + j] * NTT_Y[j]);
		b1[3 * NTT_DIM + j] = montgomery_reduce(b1[3 * NTT_DIM + j] * NTT_Y[j]);
		b0[j] = b0[j] + b0[4 * NTT_DIM + j] - b1[3 * NTT_DIM + j];


		b0[5 * NTT_DIM + j] = montgomery_reduce(b0[5 * NTT_DIM + j] * NTT_Y[j]);
		b1[4 * NTT_DIM + j] = montgomery_reduce(b1[4 * NTT_DIM + j] * NTT_Y[j]);
		b0[NTT_DIM + j] = b0[NTT_DIM + j] + b0[5 * NTT_DIM + j] - b1[j] - b1[4 * NTT_DIM + j];

		b0[6 * NTT_DIM + j] = montgomery_reduce(b0[6 * NTT_DIM + j] * NTT_Y[j]);
		b1[5 * NTT_DIM + j] = montgomery_reduce(b1[5 * NTT_DIM + j] * NTT_Y[j]);
		b0[2 * NTT_DIM + j] = b0[2 * NTT_DIM + j] + b0[6 * NTT_DIM + j] - b1[NTT_DIM + j] - b1[5 * NTT_DIM + j];

		b1[6 * NTT_DIM + j] = montgomery_reduce(b1[6 * NTT_DIM + j] * NTT_Y[j]);
		b0[3 * NTT_DIM + j] = b0[3 * NTT_DIM + j] - b1[2 * NTT_DIM + j] - b1[6 * NTT_DIM + j];
	}

	if (!mont2_inverse4(b1, b0))
		return 0;

	mont_mul4(b0, b1, t0);
	mont_mul4(b1, b1, t1);

	for (i = 0; i < 3; i++)
		for (j = 0; j < NTT_DIM; j++)
		{
			b0[(4 + i) * NTT_DIM + j] = montgomery_reduce(b0[(4 + i) * NTT_DIM + j] * NTT_Y[j]);
			b1[(4 + i) * NTT_DIM + j] = montgomery_reduce(b1[(4 + i) * NTT_DIM + j] * NTT_Y[j]);

			r->coeffs[2 * i * NTT_DIM + j] = b0[i * NTT_DIM + j] + b0[(4 + i) * NTT_DIM + j];
			r->coeffs[(2 * i + 1) * NTT_DIM + j] = -b1[i * NTT_DIM + j] - b1[(4 + i) * NTT_DIM + j];
		}

	for (i = 3; i < 4; i++)
	{
		memcpy(&r->coeffs[2 * i * NTT_DIM], &b0[i * NTT_DIM], NTT_DIM * 2);
		for (j = 0; j < NTT_DIM; j++)
			r->coeffs[(2 * i + 1) * NTT_DIM + j] = -b1[i * NTT_DIM + j];
	}

	return 1;
}
int poly_mont2_inverse_judge(const poly*a)
{
	int16_t t0[4 * NTT_DIM], t1[4 * NTT_DIM];
	int16_t b0[7 * NTT_DIM], b1[7 * NTT_DIM];

	int i, j;
	for (j = 0; j < 4; j++)
	{
		memcpy(&t0[j * NTT_DIM], &a->coeffs[2 * j * NTT_DIM], NTT_DIM * 2);
		memcpy(&t1[j * NTT_DIM], &a->coeffs[(2 * j + 1) * NTT_DIM], NTT_DIM * 2);
	}

	mont_square4(b0, t0);
	mont_square4(b1, t1);

	for (j = 0; j < NTT_DIM; j++)
	{
		b0[4 * NTT_DIM + j] = montgomery_reduce(b0[4 * NTT_DIM + j] * NTT_Y[j]);
		b1[3 * NTT_DIM + j] = montgomery_reduce(b1[3 * NTT_DIM + j] * NTT_Y[j]);
		b0[j] = b0[j] + b0[4 * NTT_DIM + j] - b1[3 * NTT_DIM + j];

		b0[5 * NTT_DIM + j] = montgomery_reduce(b0[5 * NTT_DIM + j] * NTT_Y[j]);
		b1[4 * NTT_DIM + j] = montgomery_reduce(b1[4 * NTT_DIM + j] * NTT_Y[j]);
		b0[NTT_DIM + j] = b0[NTT_DIM + j] + b0[5 * NTT_DIM + j] - b1[j] - b1[4 * NTT_DIM + j];

		b0[6 * NTT_DIM + j] = montgomery_reduce(b0[6 * NTT_DIM + j] * NTT_Y[j]);
		b1[5 * NTT_DIM + j] = montgomery_reduce(b1[5 * NTT_DIM + j] * NTT_Y[j]);
		b0[2 * NTT_DIM + j] = b0[2 * NTT_DIM + j] + b0[6 * NTT_DIM + j] - b1[NTT_DIM + j] - b1[5 * NTT_DIM + j];

		b1[6 * NTT_DIM + j] = montgomery_reduce(b1[6 * NTT_DIM + j] * NTT_Y[j]);
		b0[3 * NTT_DIM + j] = b0[3 * NTT_DIM + j] - b1[2 * NTT_DIM + j] - b1[6 * NTT_DIM + j];
	}

	return mont2_inverse4_judge(b1, b0);
}
#elif PARAM_N/NTT_DIM == 16
void poly_mont_mul(poly* r, const poly* a, const poly* b)
{
	int16_t t0[PARAM_N], t1[PARAM_N], t2[PARAM_N];
	int i, j;
	for (i = 0; i < PARAM_N / 2; i++)
	{
		t0[i] = a->coeffs[i] + a->coeffs[PARAM_N / 2 + i];
		t1[i] = b->coeffs[i] + b->coeffs[PARAM_N / 2 + i];
	}

	mont_mul8(t1, t0, t1);
	mont_mul8(t0, a->coeffs, b->coeffs);
	mont_mul8(t2, &a->coeffs[PARAM_N / 2], &b->coeffs[PARAM_N / 2]);

	for (i = 0; i < 15 * NTT_DIM; i++)
		t1[i] -= (t0[i] + t2[i]);

	for (i = 0; i < 7 * NTT_DIM; i++)
	{
		t0[8 * NTT_DIM + i] = (t0[8 * NTT_DIM + i] + t1[i]);
		t2[i] = (t1[8 * NTT_DIM + i] + t2[i]);
	}

	for (i = 0; i < 15; i++)
		for (j = 0; j < NTT_DIM; j++)
			t2[i * NTT_DIM + j] = montgomery_reduce(t2[i * NTT_DIM + j] * NTT_Y[j]);

	for (i = 0; i < 15 * NTT_DIM; i++)
		r->coeffs[i] = t0[i] + t2[i];
	for (i = 0; i < NTT_DIM; i++)
		r->coeffs[15 * NTT_DIM + i] = t1[7 * NTT_DIM + i];
}
int poly_mont2_inverse(poly* r, const poly* a)
{
	int16_t t0[8 * NTT_DIM], t1[8 * NTT_DIM];
	int16_t b0[15 * NTT_DIM], b1[15 * NTT_DIM];
	int i, j;

	for (j = 0; j < 8; j++)
		for (i = 0; i < NTT_DIM; i++)
			t0[j * NTT_DIM + i] = a->coeffs[2 * j * NTT_DIM + i];
	for (j = 0; j < 8; j++)
		for (i = 0; i < NTT_DIM; i++)
			t1[j * NTT_DIM + i] = a->coeffs[(2 * j + 1) * NTT_DIM + i];

	mont_square8(b0, t0);
	mont_square8(b1, t1);

	for (i = 8; i < 15; i++)
		for (j = 0; j < NTT_DIM; j++)
			b0[i * NTT_DIM + j] = montgomery_reduce(b0[i * NTT_DIM + j] * NTT_Y[j]);

	for (i = 7; i < 15; i++)
		for (j = 0; j < NTT_DIM; j++)
			b1[i * NTT_DIM + j] = montgomery_reduce(b1[i * NTT_DIM + j] * NTT_Y[j]);

	for (j = 0; j < 7 * NTT_DIM; j++)
		b0[j] = b0[j] + b0[8 * NTT_DIM + j];

	for (j = 0; j < 8 * NTT_DIM; j++)
		b0[j] = b0[j] - b1[7 * NTT_DIM + j];

	for (j = 0; j < 7 * NTT_DIM; j++)
		b0[NTT_DIM + j] = b0[NTT_DIM + j] - b1[j];

	if (!mont2_inverse8(b1, b0))
		return 0;

	mont_mul8(b0, b1, t0);
	mont_mul8(b1, b1, t1);

	for (i = 8; i < 15; i++)
		for (j = 0; j < NTT_DIM; j++)
			b0[i * NTT_DIM + j] = montgomery_reduce(b0[i * NTT_DIM + j] * NTT_Y[j]);

	for (i = 8; i < 15; i++)
		for (j = 0; j < NTT_DIM; j++)
			b1[i * NTT_DIM + j] = montgomery_reduce(b1[i * NTT_DIM + j] * NTT_Y[j]);

	for (i = 0; i < 7 * NTT_DIM; i++)
		b0[i] = b0[i] + b0[8 * NTT_DIM + i];

	for (i = 0; i < 7 * NTT_DIM; i++)
		b1[i] = b1[i] + b1[8 * NTT_DIM + i];

	for (i = 0; i < 8; i++)
		for (j = 0; j < NTT_DIM; j++)
		{
			r->coeffs[2 * i * NTT_DIM + j] = b0[i * NTT_DIM + j];
			r->coeffs[(2 * i + 1) * NTT_DIM + j] = -b1[i * NTT_DIM + j];
		}
	return 1;
}
int poly_mont2_inverse_judge(const poly* a)
{
	int16_t t0[8 * NTT_DIM], t1[8 * NTT_DIM];
	int16_t b0[15 * NTT_DIM], b1[15 * NTT_DIM];
	int i, j;

	for (j = 0; j < 8; j++)
		for (i = 0; i < NTT_DIM; i++)
			t0[j * NTT_DIM + i] = a->coeffs[2 * j * NTT_DIM + i];
	for (j = 0; j < 8; j++)
		for (i = 0; i < NTT_DIM; i++)
			t1[j * NTT_DIM + i] = a->coeffs[(2 * j + 1) * NTT_DIM + i];

	mont_square8(b0, t0);
	mont_square8(b1, t1);

	for (i = 8; i < 15; i++)
		for (j = 0; j < NTT_DIM; j++)
			b0[i * NTT_DIM + j] = montgomery_reduce(b0[i * NTT_DIM + j] * NTT_Y[j]);

	for (i = 7; i < 15; i++)
		for (j = 0; j < NTT_DIM; j++)
			b1[i * NTT_DIM + j] = montgomery_reduce(b1[i * NTT_DIM + j] * NTT_Y[j]);

	for (j = 0; j < 7 * NTT_DIM; j++)
		b0[j] = b0[j] + b0[8 * NTT_DIM + j];

	for (j = 0; j < 8 * NTT_DIM; j++)
		b0[j] = b0[j] - b1[7 * NTT_DIM + j];

	for (j = 0; j < 7 * NTT_DIM; j++)
		b0[NTT_DIM + j] = b0[NTT_DIM + j] - b1[j];

	return mont2_inverse8_judge(b1, b0);
}
#elif PARAM_N/NTT_DIM == 32
void poly_mont_mul(poly* r, const poly* a, const poly* b)
{
	int16_t t0[PARAM_N], t1[PARAM_N], t2[PARAM_N];
	int i, j;
	for (i = 0; i < PARAM_N / 2; i++)
	{
		t0[i] = a->coeffs[i] + a->coeffs[PARAM_N / 2 + i];
		t1[i] = b->coeffs[i] + b->coeffs[PARAM_N / 2 + i];
	}

	mont_mul16(t1, t0, t1);
	mont_mul16(t0, a->coeffs, b->coeffs);
	mont_mul16(t2, &a->coeffs[PARAM_N / 2], &b->coeffs[PARAM_N / 2]);

	for (i = 0; i < 31 * NTT_DIM; i++)
		t1[i] -= (t0[i] + t2[i]);

	for (i = 0; i < 15 * NTT_DIM; i++)
	{
		t0[16 * NTT_DIM + i] = (t0[16 * NTT_DIM + i] + t1[i]);
		t2[i] = (t1[16 * NTT_DIM + i] + t2[i]);
	}

	for (i = 0; i < 31; i++)
		for (j = 0; j < NTT_DIM; j++)
			t2[i * NTT_DIM + j] = montgomery_reduce(t2[i * NTT_DIM + j] * NTT_Y[j]);

	for (i = 0; i < 31 * NTT_DIM; i++)
		r->coeffs[i] = t0[i] + t2[i];
	for (i = 0; i < NTT_DIM; i++)
		r->coeffs[31 * NTT_DIM + i] = t1[15 * NTT_DIM + i];
}
int poly_mont2_inverse(poly* r, const poly* a)
{
	int16_t t0[16 * NTT_DIM], t1[16 * NTT_DIM];
	int16_t b0[31 * NTT_DIM], b1[31 * NTT_DIM];
	int i, j;

	for (j = 0; j < 16; j++)
	{
		memcpy(&t0[j * NTT_DIM], &a->coeffs[2 * j * NTT_DIM], NTT_DIM * 2);
		memcpy(&t1[j * NTT_DIM], &a->coeffs[(2 * j + 1) * NTT_DIM], NTT_DIM * 2);
	}

	mont_square16(b0, t0);
	mont_square16(b1, t1);

	for (i = 16; i < 31; i++)
		for (j = 0; j < NTT_DIM; j++)
			b0[i * NTT_DIM + j] = montgomery_reduce(b0[i * NTT_DIM + j] * NTT_Y[j]);

	for (i = 15; i < 31; i++)
		for (j = 0; j < NTT_DIM; j++)
			b1[i * NTT_DIM + j] = montgomery_reduce(b1[i * NTT_DIM + j] * NTT_Y[j]);

	for (j = 0; j < 15 * NTT_DIM; j++)
		b0[j] = b0[j] + b0[16 * NTT_DIM + j];

	for (j = 0; j < 16 * NTT_DIM; j++)
		b0[j] = b0[j] - b1[15 * NTT_DIM + j];

	for (j = 0; j < 15 * NTT_DIM; j++)
		b0[NTT_DIM + j] = b0[NTT_DIM + j] - b1[j];

	if (!mont2_inverse16(b1, b0))
		return 0;

	mont_mul16(b0, b1, t0);
	mont_mul16(b1, b1, t1);

	for (i = 16; i < 31; i++)
		for (j = 0; j < NTT_DIM; j++)
			b0[i * NTT_DIM + j] = montgomery_reduce(b0[i * NTT_DIM + j] * NTT_Y[j]);

	for (i = 16; i < 31; i++)
		for (j = 0; j < NTT_DIM; j++)
			b1[i * NTT_DIM + j] = montgomery_reduce(b1[i * NTT_DIM + j] * NTT_Y[j]);

	for (i = 0; i < 15 * NTT_DIM; i++)
		b0[i] = b0[i] + b0[16 * NTT_DIM + i];

	for (i = 0; i < 15 * NTT_DIM; i++)
		b1[i] = b1[i] + b1[16 * NTT_DIM + i];

	for (i = 0; i < 16; i++)
		for (j = 0; j < NTT_DIM; j++)
		{
			r->coeffs[2 * i * NTT_DIM + j] = b0[i * NTT_DIM + j];
			r->coeffs[(2 * i + 1) * NTT_DIM + j] = -b1[i * NTT_DIM + j];
		}
	return 1;
}
int poly_mont2_inverse_judge(const poly*a)
{
	int16_t t0[16 * NTT_DIM], t1[16 * NTT_DIM];
	int16_t b0[31 * NTT_DIM], b1[31 * NTT_DIM];
	int i, j;

	for (j = 0; j < 16; j++)
	{
		memcpy(&t0[j * NTT_DIM], &a->coeffs[2 * j * NTT_DIM], NTT_DIM * 2);
		memcpy(&t1[j * NTT_DIM], &a->coeffs[(2 * j + 1) * NTT_DIM], NTT_DIM * 2);
	}

	mont_square16(b0, t0);
	mont_square16(b1, t1);

	for (i = 16; i < 31; i++)
		for (j = 0; j < NTT_DIM; j++)
			b0[i * NTT_DIM + j] = montgomery_reduce(b0[i * NTT_DIM + j] * NTT_Y[j]);

	for (i = 15; i < 31; i++)
		for (j = 0; j < NTT_DIM; j++)
			b1[i * NTT_DIM + j] = montgomery_reduce(b1[i * NTT_DIM + j] * NTT_Y[j]);

	for (j = 0; j < 15 * NTT_DIM; j++)
		b0[j] = b0[j] + b0[16 * NTT_DIM + j];

	for (j = 0; j < 16 * NTT_DIM; j++)
		b0[j] = b0[j] - b1[15 * NTT_DIM + j];

	for (j = 0; j < 15 * NTT_DIM; j++)
		b0[NTT_DIM + j] = b0[NTT_DIM + j] - b1[j];

	return mont2_inverse16_judge(b1, b0);
}
#endif


void poly_add_vinv(poly *f) {
	const uint16_t qdiv2 = (PARAM_Q + 1) / 2;
	f->coeffs[0] += qdiv2;
	f->coeffs[NTT_DIM / 2] += qdiv2;
	f->coeffs[NTT_DIM / 4] += qdiv2;
	f->coeffs[NTT_DIM * 3 / 4] += qdiv2;
}

void poly_getmontgomery(poly *r)
{
	int i;
	for (i = 0; i < PARAM_N; ++i)
		r->coeffs[i] = montgomery_reduce((int32_t)r->coeffs[i]);
}