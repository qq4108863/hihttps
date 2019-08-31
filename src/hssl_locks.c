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


#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#include "foreign/vas.h"
#include "hssl_locks.h"

/*
 * OpenSSL 1.1 has a new threading implementation that no longer
 * requires the application to set its own locking callbacks.
 */

#if OPENSSL_VERSION_NUMBER < 0x10100000L

static int num_locks = 0;
static pthread_mutex_t *locks = NULL;

static void
hssl_lock_cb(int mode, int type, const char *file, int line)
{

	(void)file;
	(void)line;
	AN(locks);
	assert(type >= 0 && type < num_locks);
	if (mode & CRYPTO_LOCK)
		AZ(pthread_mutex_lock(&locks[type]));
	else
		AZ(pthread_mutex_unlock(&locks[type]));
}

void
HSSL_Locks_Init(void)
{
	int i;

	assert(locks == NULL || CRYPTO_get_locking_callback() == hssl_lock_cb);
	if (locks != NULL)
		return;

	num_locks = CRYPTO_num_locks();
	assert(num_locks > 0);
	locks = malloc(sizeof (pthread_mutex_t) * num_locks);
	AN(locks);
	for (i = 0; i < num_locks; i++)
		AZ(pthread_mutex_init(&locks[i], NULL));

	AZ(CRYPTO_get_locking_callback());
	CRYPTO_set_locking_callback(hssl_lock_cb);
}

#else

void
HSSL_Locks_Init(void)
{
}

#endif
