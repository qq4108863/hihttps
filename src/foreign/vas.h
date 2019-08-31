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


#ifndef VAS_H_INCLUDED
#define VAS_H_INCLUDED

enum vas_e {
	VAS_WRONG,
	VAS_MISSING,
	VAS_ASSERT,
	VAS_INCOMPLETE,
};

typedef void vas_f(const char *, const char *, int, const char *, enum vas_e);

extern vas_f *VAS_Fail __attribute__((__noreturn__));

#ifdef WITHOUT_ASSERTS
#define assert(e)	((void)(e))
#else /* WITH_ASSERTS */
#define assert(e)							\
do {									\
	if (!(e)) {							\
		VAS_Fail(__func__, __FILE__, __LINE__,			\
		    #e, VAS_ASSERT);					\
	}								\
} while (0)
#endif

#define xxxassert(e)							\
do {									\
	if (!(e)) {							\
		VAS_Fail(__func__, __FILE__, __LINE__,			\
		    #e, VAS_MISSING);					\
	}								\
} while (0)

/* Assert zero return value */
#define AZ(foo)		do { assert((foo) == 0); } while (0)
#define AN(foo)		do { assert((foo) != 0); } while (0)
#define XXXAZ(foo)	do { xxxassert((foo) == 0); } while (0)
#define XXXAN(foo)	do { xxxassert((foo) != 0); } while (0)
#define diagnostic(foo)	assert(foo)
#define WRONG(expl)							\
do {									\
	VAS_Fail(__func__, __FILE__, __LINE__, expl, VAS_WRONG);	\
} while (0)

#define INCOMPL()							\
do {									\
	VAS_Fail(__func__, __FILE__, __LINE__,				\
	    "", VAS_INCOMPLETE);					\
} while (0)

#endif
