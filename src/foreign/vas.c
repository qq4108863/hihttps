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


#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vas.h"

static void __attribute__((__noreturn__))
VAS_Fail_default(const char *func, const char *file, int line,
    const char *cond, enum vas_e kind)
{
	int err = errno;

	if (kind == VAS_MISSING) {
		fprintf(stderr,
		    "Missing error handling code in %s(), %s line %d:\n"
		    "  Condition(%s) not true.\n",
		    func, file, line, cond);
	} else if (kind == VAS_INCOMPLETE) {
		fprintf(stderr,
		    "Incomplete code in %s(), %s line %d:\n",
		    func, file, line);
	} else if (kind == VAS_WRONG) {
		fprintf(stderr,
		    "Wrong turn in %s(), %s line %d: %s\n",
		    func, file, line, cond);
	} else {
		fprintf(stderr,
		    "Assert error in %s(), %s line %d:\n"
		    "  Condition(%s) not true.\n",
		    func, file, line, cond);
	}
	if (err)
		fprintf(stderr,
		    "  errno = %d (%s)\n", err, strerror(err));
	abort();
}

vas_f *VAS_Fail __attribute__((__noreturn__)) = VAS_Fail_default;
