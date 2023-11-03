/*****************************************************************************
 * mod_cgi.h: Simple HTTP module
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

#ifndef __MOD_CGI_H__
#define __MOD_CGI_H__

#include "ouistiti.h"
#include "mod_document.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define CGI_OPTION_TLS 0x01

typedef struct mod_cgi_config_script_s mod_cgi_config_script_t;
struct mod_cgi_config_script_s
{
	string_t path;
	mod_cgi_config_script_t *next;
};

typedef struct mod_cgi_config_s
{
	string_t docroot;
	htaccess_t htaccess;
	mod_cgi_config_script_t *scripts;
	const char **env;
	int nbenvs;
	int chunksize;
	struct timeval timeout;
	int options;
} mod_cgi_config_t;

extern const module_t mod_cgi;

char **cgi_buildenv(const mod_cgi_config_t *config, http_message_t *request, string_t *cgi_path, string_t *path_info);
#ifdef FILE_CONFIG
typedef int (*cgi_configscript_t)(config_setting_t *setting, mod_cgi_config_t *python);
int cgienv_config(config_setting_t *configserver, config_setting_t *config, server_t *server, mod_cgi_config_t **modconfig, cgi_configscript_t configscript);
#endif

#ifdef __cplusplus
}
#endif

#endif
