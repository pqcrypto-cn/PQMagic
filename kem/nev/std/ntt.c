#include "ntt.h"
#include "params.h"
#include "reduce.h"


#if PARAM_Q == 641

const int16_t zetas[NTT_DIM] = { 154,-1,318,256,-16,100,250,40,-10,-258,-4,25,-282,160,-241,64,-32,200,-141,80,-5,-129,-2,-308,77,320,159,128,-8,50,125,20,29,-21,268,248,305,177,122,199,-210,-290,-84,-116,-153,155,67,62,-31,-287,244,-243,-105,-145,-42,-58,-306,310,134,124,-168,-232,61,-221 };

const int16_t zetas_inv[NTT_DIM] = { 221,-61,232,168,-124,-134,-310,306,58,42,145,105,243,-244,287,31,-62,-67,-155,153,116,84,290,210,-199,-122,-177,-305,-248,-268,21,-29,-20,-125,-50,8,-128,-159,-320,-77,308,2,129,5,-80,141,-200,32,-64,241,-160,282,-25,4,258,10,-40,-250,-100,16,-256,-318,1 };

void ntt(int16_t* a)
{
	int level, start, j, k, step;
	int32_t zeta;
	int16_t t;

	k = 1;
	for (level = 5; level >= 1; level--)
	{
		step = (1 << level);
		for (start = 0; start < 64; start = j + step)
		{
			zeta = zetas[k++];
			for (j = start; j < start + step; ++j)
			{
				t = montgomery_reduce(zeta * a[j + step]);
				a[j + step] = a[j] - t;
				a[j] = a[j] + t;
			}
		}
	}
	step = 1;
	for (start = 0; start < 64; start = j + step)
	{
		zeta = zetas[k++];
		for (j = start; j < start + step; ++j)
		{
			t = montgomery_reduce(zeta * a[j + step]);
			a[j + step] = barrett_reduce(a[j] - t);
			a[j] = barrett_reduce(a[j] + t);
		}
	}
}
void invntt(int16_t* a) {
	int start, level, step, j, k;
	int32_t zeta, t;

	k = 0;
	for (level = 0; level < 5; level++)
	{
		step = (1 << level);
		for (start = 0; start < 64; start = j + step) {
			zeta = zetas_inv[k++];
			for (j = start; j < start + step; ++j)
			{
				t = a[j];
				a[j] = t + a[j + step];
				t -= a[j + step];
				a[j + step] = montgomery_reduce(zeta * t);
			}
		}
	}
	step = (1 << 5);
	zeta = zetas_inv[k++];
	a[0] = barrett_reduce(a[0]);
	for (j = 0; j < step; ++j)
	{
		t = a[j];
		a[j] = t + a[j + step];
		a[j] = montgomery_reduce(10 * (int32_t)a[j]);
		t -= a[j + step];
		a[j + step] = montgomery_reduce(zeta * t);
		a[j + step] = montgomery_reduce((int32_t)a[j + step] * 10);
	}
}

#elif PARAM_Q == 1409

const static int16_t zetas[NTT_DIM] = {
	-687, -544, -284, -149, 551, -341, 599, 220,
	-22, -81, 196, -175, 354, -618, -592, 126,
	-32, -374, 157, 514, 643, 382, 676, -201,
	161, -496, 487, 320, -285, -601, -407, 615,
	-337, -152, -328, -311, 299, -116, -102, 393,
	-462, -292, -111, 552, 389, -297, 249, -172,
	-672, 600, 479, -478, -587, -432, 106, 6,
	563, -553, 364, -325, -349, 60, -93, 234
};
void ntt(int16_t *a) {
	unsigned int len, start, j, k;
	int16_t t, zeta;
	k = 1;
	for (len = 32; len > 0; len >>= 1) {
		for (start = 0; start < NTT_DIM; start = j + len) {
			zeta = zetas[k++];
			for (j = start; j < start + len; j++) {
				t = fqmul(zeta, a[j + len]);
				a[j + len] = a[j] - t;
				a[j] = a[j] + t;
			}
		}
	}
	for (int i = 0; i < NTT_DIM; i++)
		a[i] = barrett_reduce(a[i]);
}

void invntt(int16_t *a) {
	unsigned int start, len, j, k;
	int16_t t, zeta;
	const int16_t f = 1012; // mont^2/64

	k = NTT_DIM;
	for (len = 1; len < NTT_DIM; len <<= 1) {
		for (start = 0; start < NTT_DIM; start = j + len) {
			zeta = zetas[--k];
			for (j = start; j < start + len; j++) {
				t = a[j];
				a[j] = barrett_reduce(t + a[j + len]);
				a[j + len] = a[j + len] - t;
				a[j + len] = fqmul(zeta, a[j + len]);
			}
		}
	}
	for (j = 0; j < NTT_DIM; j++) {
		a[j] = fqmul(a[j], f);
	}
}

#elif PARAM_Q == 3329
const static int16_t zetas[128] = {
	-1044, -758, -359, -1517, 1493, 1422, 287, 202,
	-171, 622, 1577, 182, 962, -1202, -1474, 1468,
	573, -1325, 264, 383, -829, 1458, -1602, -130,
	-681, 1017, 732, 608, -1542, 411, -205, -1571,
	1223, 652, -552, 1015, -1293, 1491, -282, -1544,
	516, -8, -320, -666, -1618, -1162, 126, 1469,
	-853, -90, -271, 830, 107, -1421, -247, -951,
	-398, 961, -1508, -725, 448, -1065, 677, -1275,
	-1103, 430, 555, 843, -1251, 871, 1550, 105,
	422, 587, 177, -235, -291, -460, 1574, 1653,
	-246, 778, 1159, -147, -777, 1483, -602, 1119,
	-1590, 644, -872, 349, 418, 329, -156, -75,
	817, 1097, 603, 610, 1322, -1285, -1465, 384,
	-1215, -136, 1218, -1335, -874, 220, -1187, -1659,
	-1185, -1530, -1278, 794, -1510, -854, -870, 478,
	-108, -308, 996, 991, 958, -1460, 1522, 1628
};

void ntt(int16_t *a) {
	unsigned int len, start, j, k;
	int16_t t, zeta;
	k = 1;
	for (len = 64; len > 0; len >>= 1) {
		for (start = 0; start < NTT_DIM; start = j + len) {
			zeta = zetas[k++];
			for (j = start; j < start + len; j++) {
				t = fqmul(zeta, a[j + len]);
				a[j + len] = a[j] - t;
				a[j] = a[j] + t;
			}
		}
	}
	for (int i = 0; i < NTT_DIM; i++)
		a[i] = barrett_reduce(a[i]);
}

void invntt(int16_t *a) {
	unsigned int start, len, j, k;
	int16_t t, zeta;
	const int16_t f = 1441; // mont^2/128

	k = NTT_DIM;
	for (len = 1; len < NTT_DIM; len <<= 1) {
		for (start = 0; start < NTT_DIM; start = j + len) {
			zeta = zetas[--k];
			for (j = start; j < start + len; j++) {
				t = a[j];
				a[j] = barrett_reduce(t + a[j + len]);
				a[j + len] = a[j + len] - t;
				a[j + len] = fqmul(zeta, a[j + len]);
			}
		}
	}
	for (j = 0; j < NTT_DIM; j++) {
		a[j] = fqmul(a[j], f);
	}
}

#elif PARAM_Q == 769
const static int16_t zetas[128] = {
	171, -164, -81, 361, -186, 3, 250, 120,
	-129, -308, 223, -16, -143, 362, -337, -131,
	-75, -36, 76, 98, 203, 282, -339, -255,
	178, 270, 199, 34, -369, 192, -149, -10,
	-80, -346, -124, 2, 114, 147, -54, -272,
	-169, 288, 161, -15, -86, 51, -364, -267,
	170, -226, -121, 188, -50, -24, 307, -191,
	263, 157, -246, 128, 375, 180, -380, 279,
	-341, -379, 202, 220, 236, 21, 212, 71,
	-134, 151, 23, -112, -232, 227, -52, -148,
	244, -252, -237, -83, -117, -333, -66, -247,
	-292, 352, -145, 238, -276, -194, -274, -70,
	209, -115, -99, 14, 29, 260, -378, -366,
	355, -291, 358, -105, 167, 357, -241, -331,
	-348, -44, -78, -222, -350, -168, -158, 201,
	303, 330, -184, 127, 318, -278, -353, -354
};

void ntt(int16_t *a) {
	unsigned int len, start, j, k;
	int16_t t, zeta;
	k = 1;
	for (len = 64; len > 0; len >>= 1) {
		for (start = 0; start < NTT_DIM; start = j + len) {
			zeta = zetas[k++];
			for (j = start; j < start + len; j++) {
				t = fqmul(zeta, a[j + len]);
				a[j + len] = a[j] - t;
				a[j] = a[j] + t;
			}
		}
	}
	for (int i = 0; i < NTT_DIM; i++)
		a[i] = barrett_reduce(a[i]);
}

void invntt(int16_t *a) {
	unsigned int start, len, j, k;
	int16_t t, zeta;
	const int16_t f = 655; // mont^2/128

	k = NTT_DIM;
	for (len = 1; len < NTT_DIM; len <<= 1) {
		for (start = 0; start < NTT_DIM; start = j + len) {
			zeta = zetas[--k];
			for (j = start; j < start + len; j++) {
				t = a[j];
				a[j] = barrett_reduce(t + a[j + len]);
				a[j + len] = a[j + len] - t;
				a[j + len] = fqmul(zeta, a[j + len]);
			}
		}
	}
	for (j = 0; j < NTT_DIM; j++) {
		a[j] = fqmul(a[j], f);
	}
}

#endif
