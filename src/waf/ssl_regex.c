/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "ssl_regex.h"



#ifdef USE_PCRE
#include <pcre.h>
#include <pcreposix.h>
 
 /* For pre-8.20 PCRE compatibility */
#ifndef PCRE_STUDY_JIT_COMPILE
#define PCRE_STUDY_JIT_COMPILE 0
#endif
 
#elif USE_PCRE2
#include <pcre2.h>
#include <pcre2posix.h>
 
#else /* no PCRE, nor PCRE2 */
#include <regex.h>
#endif


 struct my_regex {
#ifdef USE_PCRE
	pcre *reg;
	pcre_extra *extra;
#ifdef USE_PCRE_JIT
#ifndef PCRE_CONFIG_JIT
#error "The PCRE lib doesn't support JIT. Change your lib, or remove the option USE_PCRE_JIT."
#endif
#endif
#elif USE_PCRE2
	pcre2_code *reg;
#else /* no PCRE */
	regex_t regex;
#endif
};


/* This function apply regex. It take const null terminated char as input.
 * If the function doesn't match, it returns false, else it returns true.
 * When it is compiled with JIT, this function execute strlen on the subject.
 * Currently the only supported flag is REG_NOTBOL.
 */
int ngx_regex_exec_match(const struct my_regex *preg, const char *subject,
                     size_t nmatch, regmatch_t pmatch[], int flags) {
#if defined(USE_PCRE) || defined(USE_PCRE_JIT) || defined(USE_PCRE2) || defined(USE_PCRE2_JIT)
	int ret;
#ifdef USE_PCRE2
	PCRE2_SIZE *matches;
	pcre2_match_data *pm;
#else
	int matches[MAX_MATCH * 3];
#endif
	int enmatch;
	int i;
	int options;

	/* Silently limit the number of allowed matches. max
	 * match i the maximum value for match, in fact this
	 * limit is not applyied.
	 */

	enmatch = nmatch;
	if (enmatch > MAX_MATCH)
		enmatch = MAX_MATCH;

	options = 0;
	if (flags & REG_NOTBOL)
#ifdef USE_PCRE2
		options |= PCRE2_NOTBOL;
#else
		options |= PCRE_NOTBOL;
#endif

	/* The value returned by pcre_exec()/pcre2_match() is one more than the highest numbered
	 * pair that has been set. For example, if two substrings have been captured,
	 * the returned value is 3. If there are no capturing subpatterns, the return
	 * value from a successful match is 1, indicating that just the first pair of
	 * offsets has been set.
	 *
	 * It seems that this function returns 0 if it detects more matches than available
	 * space in the matches array.
	 */
#ifdef USE_PCRE2
	pm = pcre2_match_data_create_from_pattern(preg->reg, NULL);
	ret = pcre2_match(preg->reg, (PCRE2_SPTR)subject, (PCRE2_SIZE)strlen(subject), 0, options, pm, NULL);

	if (ret < 0) {
		pcre2_match_data_free(pm);
		return 0;
	}

	matches = pcre2_get_ovector_pointer(pm);
#else
	ret = pcre_exec(preg->reg, preg->extra, subject, strlen(subject), 0, options, matches, enmatch * 3);

	if (ret < 0)
		return 0;
#endif

	if (ret == 0)
		ret = enmatch;

	for (i=0; i<nmatch; i++) {
		/* Copy offset. */
		if (i < ret) {
			pmatch[i].rm_so = matches[(i*2)];
			pmatch[i].rm_eo = matches[(i*2)+1];
			continue;
		}
		/* Set the unmatvh flag (-1). */
		pmatch[i].rm_so = -1;
		pmatch[i].rm_eo = -1;
	}
#ifdef USE_PCRE2
	pcre2_match_data_free(pm);
#endif
	return 1;
#else
	int match;

	flags &= REG_NOTBOL;
	match = regexec(&preg->regex, subject, nmatch, pmatch, flags);
	if (match == REG_NOMATCH)
		return 0;
	return 1;
#endif
}

ngx_int_t ngx_regex_compile(ngx_regex_compile_t *rc)
{

#if defined(USE_PCRE) || defined(USE_PCRE_JIT)
	int               n, erroff;
    char             *p;
    pcre             *re;
    const char       *errstr;

	
	re = pcre_compile((const char *) rc->pattern.data, (int) rc->options,
						 &errstr, &erroff, NULL);

	if (re == NULL)
		return NGX_ERROR;

	rc->regex = ngx_pcalloc(rc->pool, sizeof(ngx_regex_t));
    if (rc->regex == NULL) {
       return NGX_ERROR;
    }

	 rc->regex->code = re;


#else

	int flags = REG_EXTENDED;

	
	flags |= REG_ICASE;	
	flags |= REG_NOSUB;
	
	if (regcomp(&rc->re, (const char *)rc->pattern.data, flags) != 0) 	
	{
		//printf("ngx_regex_compile %s error!!!!!!!!!!\n",rc->pattern.data);	
		return NGX_CONF_ERROR;
	}
	//printf("ngx_regex_compile %s ok............................\n",rc->pattern.data);	
	return NGX_OK;

#endif	
	return NGX_OK;
	
}

int ngx_regex_comp(const char *str, struct my_regex *regex, int cs, int cap, char **err)
{
#if defined(USE_PCRE) || defined(USE_PCRE_JIT)
	int flags = 0;
	const char *error;
	int erroffset;

	if (!cs)
		flags |= PCRE_CASELESS;
	if (!cap)
		flags |= PCRE_NO_AUTO_CAPTURE;

	regex->reg = pcre_compile(str, flags, &error, &erroffset, NULL);
	if (!regex->reg) {
		//memprintf(err, "regex '%s' is invalid (error=%s, erroffset=%d)", str, error, erroffset);
		printf("regex '%s' is invalid (error=%s, erroffset=%d)", str, error, erroffset);
		return 0;
	}

	regex->extra = pcre_study(regex->reg, PCRE_STUDY_JIT_COMPILE, &error);
	if (!regex->extra && error != NULL) {
		pcre_free(regex->reg);
		//memprintf(err, "failed to compile regex '%s' (error=%s)", str, error);
		printf("failed to compile regex '%s' (error=%s)", str, error);
		return 0;
	}
#elif defined(USE_PCRE2) || defined(USE_PCRE2_JIT)
	int flags = 0;
	int errn;
#if defined(USE_PCRE2_JIT)
	int jit;
#endif
	PCRE2_UCHAR error[256];
	PCRE2_SIZE erroffset;

	if (!cs)
		flags |= PCRE2_CASELESS;
	if (!cap)
		flags |= PCRE2_NO_AUTO_CAPTURE;

	regex->reg = pcre2_compile((PCRE2_SPTR)str, PCRE2_ZERO_TERMINATED, flags, &errn, &erroffset, NULL);
	if (!regex->reg) {
		pcre2_get_error_message(errn, error, sizeof(error));
		memprintf(err, "regex '%s' is invalid (error=%s, erroffset=%zu)", str, error, erroffset);
		return 0;
	}

#if defined(USE_PCRE2_JIT)
	jit = pcre2_jit_compile(regex->reg, PCRE2_JIT_COMPLETE);
	/*
	 * We end if it is an error not related to lack of JIT support
	 * in a case of JIT support missing pcre2_jit_compile is "no-op"
	 */
	if (jit < 0 && jit != PCRE2_ERROR_JIT_BADOPTION) {
		pcre2_code_free(regex->reg);
		memprintf(err, "regex '%s' jit compilation failed", str);
		return 0;
	}
#endif

#else
	int flags = REG_EXTENDED;

	if (!cs)
		flags |= REG_ICASE;
	if (!cap)
		flags |= REG_NOSUB;

	if (regcomp(&regex->regex, str, flags) != 0) {	
		return 0;
	}
#endif
	return 1;
}



