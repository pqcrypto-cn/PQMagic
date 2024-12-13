#ifndef CBD_H
#define CBD_H

#include <stdint.h>
#include "poly.h"

#define cbd_etas AIGIS_ENC_NAMESPACE(cbd_etas)
void cbd_etas(poly  *r, const uint8_t *buf);

#define cbd_etae AIGIS_ENC_NAMESPACE(cbd_etae)
void cbd_etae(poly  *r, const uint8_t *buf);
#endif
