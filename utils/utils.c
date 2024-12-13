#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "utils.h"

void print_uchar(FILE *fp, uint8_t *data, size_t len) {
	if(fp != NULL) {
		for(size_t i = 0; i < len; i++) {
			fprintf(fp, "0x%02x ", data[i]);
		}
		fprintf(fp, "\n");
	} else {
		for(size_t i = 0; i < len; i++) {
			printf("0x%02x ", data[i]);
		}
		printf("\n");
	}
}