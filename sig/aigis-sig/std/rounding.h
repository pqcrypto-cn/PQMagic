#ifndef ROUNDING_H
#define ROUNDING_H

#include <stdint.h>
#include "params.h"
#include "reduce.h"

#define power2round AIGIS_SIG_NAMESPACE(power2round)
uint32_t power2round(const uint32_t a, uint32_t *a0);
#define decompose AIGIS_SIG_NAMESPACE(decompose)
uint32_t decompose(uint32_t a, uint32_t *a0);
#define make_hint AIGIS_SIG_NAMESPACE(make_hint)
unsigned int make_hint(const uint32_t a, const uint32_t b); 
#define use_hint AIGIS_SIG_NAMESPACE(use_hint)
uint32_t use_hint(const uint32_t a, const unsigned int hint);

#endif
