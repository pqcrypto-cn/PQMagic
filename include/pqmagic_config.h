#ifndef PQMAGIC_CONFIG_H
#define PQMAGIC_CONFIG_H

#define GLOBAL_NAMESPACE(s) pqmagic_global_##s 

#if defined(_WIN32) || defined(_WIN64)
    #define PQMAGIC_EXPORT __declspec(dllexport)
#else
    #define PQMAGIC_EXPORT
#endif

#endif
