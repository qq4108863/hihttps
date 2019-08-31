/* 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * For more ,please contact QQ/wechat:4108863 mail:4108863@qq.com
 */


#ifndef VSA_H_INCLUDED
#define VSA_H_INCLUDED

struct suckaddr;
extern const int vsa_suckaddr_len;

int VSA_Sane(const struct suckaddr *);
unsigned VSA_Port(const struct suckaddr *);
int VSA_Compare(const struct suckaddr *, const struct suckaddr *);
int VSA_Compare_IP(const struct suckaddr *, const struct suckaddr *);
struct suckaddr *VSA_Clone(const struct suckaddr *sua);

const void *VSA_Get_Sockaddr(const struct suckaddr *, socklen_t *sl);
int VSA_Get_Proto(const struct suckaddr *);

/*
 * 's' is a sockaddr of some kind, 'sal' is its length
 */
struct suckaddr *VSA_Malloc(const void *s, unsigned  sal);

/*
 * 'd' SHALL point to vsa_suckaddr_len aligned bytes of storage,
 * 's' is a sockaddr of some kind, 'sal' is its length.
 */
struct suckaddr *VSA_Build(void *d, const void *s, unsigned sal);

#endif
