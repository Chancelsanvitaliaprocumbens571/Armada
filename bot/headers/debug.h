#pragma once

#ifdef DEBUG
#include <stdio.h>
#define debug(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#define debug(fmt, ...) do {} while(0)
#endif
