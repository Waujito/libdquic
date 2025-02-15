#ifndef DQUIC_OS_PORT_H
#define DQUIC_OS_PORT_H

#include <stdint.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>

#ifdef __GNUC__
#define DQUIC_PACK__
#define DQUIC__PACK __attribute__((__packed__))
#endif

#ifdef _MSC_VER
#define DQUIC_PACK__ __pragma( pack(push, 1) ) 
#define DQUIC__PACK __pragma( pack(pop))
#endif


#endif /* DQUIC_OS_PORT_H */
