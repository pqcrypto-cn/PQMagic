/*
 *  SPDX-License-Identifier: MIT
 */

#include "instances.h"
#include "parameters.h"

const char* sig_get_param_name(sig_paramid_t paramid) {
  switch (paramid) {
  case PARAMETER_SET_INVALID:
    return "PARAMETER_SET_INVALID";
  case RESOLVED_ALPHA_160S:
    return "RESOLVED_ALPHA_160S";
  case RESOLVED_ALPHA_160F:
    return "RESOLVED_ALPHA_160F";
  case RESOLVED_ALPHA_256S:
    return "RESOLVED_ALPHA_256S";
  case RESOLVED_ALPHA_256F:
    return "RESOLVED_ALPHA_256F";
  case RESOLVED_ALPHA_384S:
    return "RESOLVED_ALPHA_384S";
  case RESOLVED_ALPHA_384F:
    return "RESOLVED_ALPHA_384F";
  case RESOLVED_ALPHA_512S:
    return "RESOLVED_ALPHA_512S";
  case RESOLVED_ALPHA_512F:
    return "RESOLVED_ALPHA_512F";
  default:
    return "PARAMETER_SET_MAX_INDEX";
  }
}

#define CALC_TAU1(name) ((name##_CSP - name##_POW_LEVEL) % name##_TAU)
#define CALC_TAU0(name) (name##_TAU - CALC_TAU1(name))
#define CALC_L(name)                                                                               \
  (CALC_TAU1(name) * (1 << CALC_K(name)) + CALC_TAU0(name) * (1 << (CALC_K(name) - 1)))
#define CALC_K(name) (((name##_CSP - name##_POW_LEVEL) / (name##_TAU)) + 1)

#define PARAMS(name)                                                                               \
  {                                                                                                \
      name##_CSP,                                                                               \
      name##_TAU,                                                                                  \
      name##_POW_LEVEL,                                                                              \
      name##_T_OPEN,                                                                               \
      name##_LENWIT,                                                                                  \
      CALC_K(name),                                                                                \
      CALC_TAU0(name),                                                                             \
      CALC_TAU1(name),                                                                             \
      CALC_L(name),                                                                                \
      name##_SIG_SIZE,                                                                             \
      name##_OWF_INPUT_SIZE,                                                                       \
      name##_OWF_OUTPUT_SIZE,                                                                      \
      name##_RSD_CODE_LENGTH,                                                                      \
      name##_RSD_DIMENSION,                                                                        \
      name##_RSD_NOISE_WEIGHT,                                                                     \
      name##_RSD_BLOCK_SIZE,                                                                       \
      name##_RSD_WITNESS_BITS,                                                                     \
  }

#define RESOLVED_ALPHA_160S_PARAMS PARAMS(RESOLVED_ALPHA_160S)
#define RESOLVED_ALPHA_160F_PARAMS PARAMS(RESOLVED_ALPHA_160F)
#define RESOLVED_ALPHA_256S_PARAMS PARAMS(RESOLVED_ALPHA_256S)
#define RESOLVED_ALPHA_256F_PARAMS PARAMS(RESOLVED_ALPHA_256F)
#define RESOLVED_ALPHA_384S_PARAMS PARAMS(RESOLVED_ALPHA_384S)
#define RESOLVED_ALPHA_384F_PARAMS PARAMS(RESOLVED_ALPHA_384F)
#define RESOLVED_ALPHA_512S_PARAMS PARAMS(RESOLVED_ALPHA_512S)
#define RESOLVED_ALPHA_512F_PARAMS PARAMS(RESOLVED_ALPHA_512F)

#define CASE_PARAM(P)                                                                              \
  case P: {                                                                                        \
    static const sig_paramset_t params = P##_PARAMS;                                             \
    return &params;                                                                                \
  }

const sig_paramset_t* sig_get_paramset(sig_paramid_t paramid) {
  switch (paramid) {
    CASE_PARAM(RESOLVED_ALPHA_160S)
    CASE_PARAM(RESOLVED_ALPHA_160F)
    CASE_PARAM(RESOLVED_ALPHA_256S)
    CASE_PARAM(RESOLVED_ALPHA_256F)
    CASE_PARAM(RESOLVED_ALPHA_384S)
    CASE_PARAM(RESOLVED_ALPHA_384F)
    CASE_PARAM(RESOLVED_ALPHA_512S)
    CASE_PARAM(RESOLVED_ALPHA_512F)
  default:
    return NULL;
  }
}
