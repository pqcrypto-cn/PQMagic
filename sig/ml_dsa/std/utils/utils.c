#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "utils.h"

void print_poly(FILE *fp, poly *p) {
    if(!fp) {
        fp = stdout;
    }
    for(int i = 0; i < N; i++) {
        fprintf(fp, "0x%x, ", p->coeffs[i]);
    }
    fprintf(fp, "\n");
}

void print_polyvecl(FILE *fp, polyvecl *pvec) {
    if(!fp) {
        fp = stdout;
    }
	for(int i = 0; i < L; i++) {
		fprintf(fp, "vec %d: ", i);
        print_poly(fp, &(pvec->vec[i]));
	}
}

void print_polyveck(FILE *fp, polyveck *pvec) {
    if(!fp) {
        fp = stdout;
    }
	for(int i = 0; i < K; i++) {
		fprintf(fp, "vec %d: ", i);
        print_poly(fp, &(pvec->vec[i]));
	}
}