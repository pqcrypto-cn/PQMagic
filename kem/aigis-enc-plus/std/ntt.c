#include "inttypes.h"
#include "ntt.h"
#include "params.h"
#include "reduce.h"



#if PARAM_Q == 3329 && NTT_DIM == 128
const int16_t zetas[PARAM_N] = { -1044,-758,-359,-1517,1493,1422,287,202,-171,622,1577,182,962,-1202,-1474,1468,573,-1325,264,383,-829,1458,-1602,-130,-681,1017,732,608,-1542,411,-205,-1571,1223,652,-552,1015,-1293,1491,-282,-1544,516,-8,-320,-666,-1618,-1162,126,1469,-853,-90,-271,830,107,-1421,-247,-951,-398,961,-1508,-725,448,-1065,677,-1275,-1103,430,555,843,-1251,871,1550,105,422,587,177,-235,-291,-460,1574,1653,-246,778,1159,-147,-777,1483,-602,1119,-1590,644,-872,349,418,329,-156,-75,817,1097,603,610,1322,-1285,-1465,384,-1215,-136,1218,-1335,-874,220,-1187,-1659,-1185,-1530,-1278,794,-1510,-854,-870,478,-108,-308,996,991,958,-1460,1522,1628 };

const int16_t zetas_inv[PARAM_N] = { -1628,-1522,1460,-958,-991,-996,308,108,-478,870,854,1510,-794,1278,1530,1185,1659,1187,-220,874,1335,-1218,136,1215,-384,1465,1285,-1322,-610,-603,-1097,-817,75,156,-329,-418,-349,872,-644,1590,-1119,602,-1483,777,147,-1159,-778,246,-1653,-1574,460,291,235,-177,-587,-422,-105,-1550,-871,1251,-843,-555,-430,1103,1275,-677,1065,-448,725,1508,-961,398,951,247,1421,-107,-830,271,90,853,-1469,-126,1162,1618,666,320,8,-516,1544,282,-1491,1293,-1015,552,-652,-1223,1571,205,-411,1542,-608,-732,-1017,681,130,1602,-1458,829,-383,-264,1325,-573,-1468,1474,1202,-962,-182,-1577,-622,171,-202,-287,-1422,-1493,1517,359,266 };

#elif PARAM_Q == 641 && NTT_DIM == 64

const int16_t zetas[NTT_DIM] = { 154,-1,318,256,-16,100,250,40,-10,-258,-4,25,-282,160,-241,64,-32,200,-141,80,-5,-129,-2,-308,77,320,159,128,-8,50,125,20,29,-21,268,248,305,177,122,199,-210,-290,-84,-116,-153,155,67,62,-31,-287,244,-243,-105,-145,-42,-58,-306,310,134,124,-168,-232,61,-221 };

const int16_t zetas_inv[NTT_DIM] = { 221,-61,232,168,-124,-134,-310,306,58,42,145,105,243,-244,287,31,-62,-67,-155,153,116,84,290,210,-199,-122,-177,-305,-248,-268,21,-29,-20,-125,-50,8,-128,-159,-320,-77,308,2,129,5,-80,141,-200,32,-64,241,-160,282,-25,4,258,10,-40,-250,-100,16,-256,-318,-10 };

#endif 

#if NTT_DIM == 128
void ntt(int16_t* a)
{
	int level, start, j, k, step;
	int32_t zeta;
	int16_t t;

	k = 1;
	for (level = 6; level >= 1; level--)
	{
		step = (1 << level);
		for (start = 0; start < 128; start = j + step)
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
	for (start = 0; start < 128; start = j + step)
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
	for (level = 0; level < 2; level++)
	{
		step = (1 << level);
		for (start = 0; start < 128; start = j + step) {
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

	step = (1 << 2);
	for (start = 0; start < 128; start = j + step) {
		zeta = zetas_inv[k++];
		for (j = start; j < start + step; ++j)
		{
			t = a[j];
			a[j] = barrett_reduce(t + a[j + step]);
			t -= a[j + step];
			a[j + step] = montgomery_reduce(zeta * t);
		}
	}

	for (level = 3; level < 5; level++)
	{
		step = (1 << level);
		for (start = 0; start < 128; start = j + step) {
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
	for (start = 0; start < 128; start = j + step) {
		zeta = zetas_inv[k++];
		for (j = start; j < start + step; ++j)
		{
			t = a[j];
			a[j] = barrett_reduce(t + a[j + step]);
			t -= a[j + step];
			a[j + step] = montgomery_reduce(zeta * t);
		}
	}
	step = (1 << 6);
	for (start = 0; start < 128; start = j + step) {
		zeta = zetas_inv[k++];
		for (j = start; j < start + step; ++j)
		{
			t = a[j];
			a[j] = t + a[j + step];
			a[j] = montgomery_reduce(512 * (int32_t)a[j]);
			t -= a[j + step];
			a[j + step] = montgomery_reduce(zeta * t);
		}
	}
}
#elif NTT_DIM == 64
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
		t = a[j];//barrett_reduce(a[j]);
		a[j] = t + a[j + step];
		a[j] = montgomery_reduce(1024 * (int32_t)a[j]);
		t -= a[j + step];
		a[j + step] = montgomery_reduce(zeta * t);
	}
}
#endif
