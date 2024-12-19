/*****************************************************************************
 * mod_date.c: callbacks and management of connection
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "ouistiti/log.h"
#include "ouistiti/httpserver.h"
#include "mod_date.h"

static int _date_connector(void *arg, http_message_t *request, http_message_t *response);

void *mod_date_create(http_server_t *server)
{
	httpserver_addconnector(server, _date_connector, NULL, CONNECTOR_SERVER, str_date);

	return (void *)-1;
}

void mod_date_destroy(void *mod)
{
}

static int _date_connector(void *arg, http_message_t *request, http_message_t *response)
{
	time_t t;
	struct tm *tmp;

	t = time(NULL);
	tmp = gmtime(&t);
	char timestring[32];
	int len = -1;
	len = strftime(timestring, 32, "%a, %d %b %Y %T GMT", tmp);
	dbg("date: %s", timestring);
	if (len > 0)
		httpmessage_addheader(response, str_date, timestring, len);
	/* reject the request to allow other connectors to set the response */
	return EREJECT;
}

const module_t mod_date =
{
	.name = str_date,
	.create = (module_create_t)mod_date_create,
	.destroy = mod_date_destroy,
};
#ifdef MODULES
extern module_t mod_info __attribute__ ((weak, alias ("mod_date")));
#endif
