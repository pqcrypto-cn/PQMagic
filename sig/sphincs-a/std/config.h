#ifndef CONFIG_H
#define CONFIG_H

#define CONCAT(a, b) a##_##b
#define XCONCAT(a, b) CONCAT(a, b) 
#define XCONCAT3(a, b, c) XCONCAT(XCONCAT(a, b), c) 
#define XCONCAT5(a, b, c, d, e) XCONCAT3(XCONCAT(a, b), XCONCAT(c, d), e) 

#define SPX_NAMESPACE(s) XCONCAT5(pqmagic_sphincs_a, SPHINCS_A_HASH_MODE_NAMESPACE, THASH, std, s)

#endif
