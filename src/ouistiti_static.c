/*****************************************************************************
 * ouistiti_static.c: modules initialisation
 * this file is part of https://github.com/ouistiti-project/ouistiti
 *****************************************************************************
 * Copyright (C) 2016-2017
 *
 * Authors: Marc Chalain <marc.chalain@gmail.com>
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
#include <stdio.h>
#include <sys/stat.h>

#include "ouistiti/httpserver.h"
#include "ouistiti/log.h"
#include "ouistiti.h"

#include "mod_clientfilter.h"
#include "mod_tls.h"
#include "mod_cors.h"
#include "mod_auth.h"
#include "mod_authmngt.h"
#include "mod_methodlock.h"
#include "mod_server.h"
#include "mod_cookie.h"
#include "mod_userfilter.h"
#include "mod_document.h"
#include "mod_cgi.h"
#include "mod_websocket.h"
#include "mod_webstream.h"
#include "mod_vhost.h"
#include "mod_redirect404.h"
#include "mod_redirect.h"
#include "mod_tinysvcmdns.h"
#include "mod_upgrade.h"

static const module_t *default_modules[] =
{
#if defined TLS
	&mod_tls,
#endif
#if defined VHOST
	&mod_vhost,
#endif
#if defined CLIENTFILTER
	&mod_clientfilter,
#endif
#if defined COOKIE
	&mod_cookie,
#endif
#if defined AUTH
	&mod_auth,
#endif
#if defined AUTHZ_MANAGER
	&mod_authmngt,
#endif
#if defined USERFILTER
	&mod_userfilter,
#endif
#if defined METHODLOCK
	&mod_methodlock,
#endif
#if defined SERVERHEADER
	&mod_server,
#endif
#if defined CGI
	&mod_cgi,
#endif
#if defined DOCUMENT
	&mod_document,
#endif
#if defined WEBSTREAM
	&mod_webstream,
#endif
#if defined WEBSOCKET
	&mod_websocket,
#endif
#if defined REDIRECT
	&mod_redirect404,
	&mod_redirect,
#endif
#if defined CORS
	&mod_cors,
#endif
#if defined TINYSVCMDNS
	&mod_tinysvcmdns,
#endif
#if defined UPGRADE
	&mod_upgrade,
#endif
	NULL
};

int ouistiti_initmodules(const char *UNUSED(pkglib))
{
	for (int i = 0; default_modules[i] != NULL; i++)
	{
		ouistiti_registermodule(default_modules[i], NULL);
	}
	return ESUCCESS;
}

void ouistiti_finalizemodule(void *dh)
{
}
