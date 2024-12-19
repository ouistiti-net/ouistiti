/*****************************************************************************
 * docuemtn_htaccess.c: check accessfile feature
 * this file is part of https://github.com/ouistiti-project/ouistiti
 *****************************************************************************
 * Copyright (C) 2016-2017
 *
 * Authors: Marc Chalain <marc.chalain@gmail.com
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject
 * to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *****************************************************************************/
#include <stdlib.h>
#include <stdio.h>

#ifdef FILE_CONFIG
#include <libconfig.h>
#endif

#include "ouistiti/httpserver.h"
#include "ouistiti/utils.h"
#include "ouistiti/log.h"
#include "mod_document.h"

const char str_wildcard[] = "*";

#ifdef FILE_CONFIG
int htaccess_config(config_setting_t *setting, htaccess_t *htaccess)
{
	const char *allow = NULL;;
	const char *deny = str_wildcard;;
	int denylast = 0;

	config_setting_lookup_string(setting, "allow", &allow);
	config_setting_lookup_string(setting, "deny", &deny);

	config_setting_lookup_bool(setting, "denylast", &denylast);

	string_store(&htaccess->allow, allow, -1);
	if (!denylast)
		string_store(&htaccess->denyfirst, deny, -1);
	else
		string_store(&htaccess->denylast, deny, -1);
	return ESUCCESS;
}
#endif

int htaccess_check(const htaccess_t *htaccess, const char *uri, const char **path_info)
{
	if (htaccess->denyfirst.data != NULL && utils_searchexp(uri, htaccess->denyfirst.data, NULL) == ESUCCESS)
	{
		return  EREJECT;
	}
	if (htaccess->allow.data != NULL && utils_searchexp(uri, htaccess->allow.data, path_info) == ESUCCESS)
	{
		return  ESUCCESS;
	}
	if (htaccess->denylast.data != NULL && utils_searchexp(uri, htaccess->denylast.data, NULL) == ESUCCESS)
	{
		return  EREJECT;
	}
	return ESUCCESS;
}
