#ifndef TOOLS_H
#define TOOLS_H

#include <time.h>
int two_adic_valuation(int n);

clock_t tic();
float tac();                                 /* time in ms since last tic */
float TAC(const char *str);                  /* same, but prints it with label 'str' */
float toc(const clock_t t);                  /* time in ms since t */
float TOC(const clock_t t, const char *str); /* same, but prints it with label 'str' */
float TOC_clock(const clock_t t, const char *str);

clock_t dclock(const clock_t t); // return the clock cycle diff between now and t
float clock_to_time(const clock_t t,
                    const char *str); // convert the number of clock cycles t to time
float clock_print(const clock_t t, const char *str);
#endif
