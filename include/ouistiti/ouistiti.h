/*****************************************************************************
 * config.h: configuration file parser
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

#ifndef __OUISTITI_CONFIG_H__
#define __OUISTITI_CONFIG_H__

#ifndef MAX_SERVERS
#define MAX_SERVERS 4
#endif

typedef struct server_s server_t;

typedef struct module_s module_t;
typedef struct modulesconfig_s modulesconfig_t;
typedef struct serverconfig_s serverconfig_t;
typedef struct module_list_s module_list_t;

#define WEBSOCKET_REALTIME 0x01

#define MODULE_VERSION_CURRENT 0x0001
#define MODULE_VERSION_DEPRECATED 0x8000
typedef void *(*module_configure_v0_t)(void *parser, server_t *server);
typedef int (*module_configure_t)(void *parser, server_t *server, int index, void **config);
typedef void *(*module_create_t)(http_server_t *server, void *config);
typedef void (*module_destroy_t)(void*);
struct module_s
{
	const char *name;
	module_configure_t configure;
	module_create_t create;
	module_destroy_t destroy;
	unsigned short version;
};

struct module_list_s
{
	const module_t *module;
	void *dh;
	struct module_list_s *next;
};

typedef struct mod_s mod_t;
struct mod_s
{
	void *obj;
	const module_t *ops;
	mod_t *next;
};

struct serverconfig_s
{
	void *configfile;
	http_server_config_t *server;
	const char *root;
	void *modulesconfig;
};

typedef struct ouistiticonfig_s
{
	void *configfile;
	char *user;
	const char *init_d;
	serverconfig_t *config[MAX_SERVERS];
	int nservers;
} ouistiticonfig_t;

ouistiticonfig_t *ouistiticonfig_create(const char *filepath);
void ouistiticonfig_destroy(ouistiticonfig_t *ouistiticonfig);

int ouistiti_setlogfile(const char *logfile, size_t logmax, const char *owner);

int ouistiti_initmodules(const char *pkglib);
void ouistiti_finalizemodule(void *dh);
typedef void *(*configure_t)(void *data, const module_t *module, server_t *server);
void ouistiti_registermodule(const module_t *module, void *dh);
const module_list_t *ouistiti_modules(server_t *server);
int ouistiti_issecure(server_t *server);
http_server_t *ouistiti_httpserver(server_t *server);
serverconfig_t *ouistiti_serverconfig(server_t *server);

int ouistiti_setprocessowner(const char *user);

typedef struct string_s string_t;
struct string_s
{
	const char *data;
	size_t length;
	size_t size;
};

#define STRING_REF(string) string, sizeof(string)-1
#define STRING_INFO(string) string.data, string.length
#define STRING_DCL(string) {.data=string, .size=sizeof(string), .length=sizeof(string)-1}
int string_store(string_t *str, const char *pointer, size_t length);
int string_cmp(const string_t *str, const char *cmp, size_t length);
int string_contain(const string_t *str, const char *cmp, size_t length, const char sep);
int string_cpy(string_t *str, const char *source, size_t length);
int string_empty(const string_t *str);
const char *string_toc(const string_t *str);
size_t string_length(const string_t *str);

extern const char str_servername[9];

extern const char str_http[5];
extern const char str_https[6];

/**
 * strings defined in libouistiti
 */
extern const char str_get[4];
extern const char str_post[5];
extern const char str_head[5];

extern const char str_put[4];
extern const char str_delete[7];
extern const char str_options[8];

extern const char str_authenticate[17];
extern const char str_authorization[14];
extern const char str_Cookie[7];
extern const char str_cachecontrol[14];
extern const char str_xtoken[13];
extern const char str_xuser[14];
extern const char str_xgroup[15];
extern const char str_xhome[14];
extern const char str_upgrade_insec_req[26];
extern const char str_connection[11];
extern const char str_upgrade[8];
extern const char str_websocket[10];
extern const char str_sec_ws_protocol[23];
extern const char str_sec_ws_accept[21];
extern const char str_sec_ws_key[18];
extern const char str_date[5];
extern const char str_authorization_code[5];
extern const char str_access_token[12];
extern const char str_state[14];
extern const char str_expires[8];

extern const char str_form_urlencoded[34];
extern const char str_multipart_replace[26];

extern const char str_boundary[6];

extern const char str_token[6];
extern const char str_anonymous[10];
extern const char str_user[5];
extern const char str_group[6];
extern const char str_home[5];
extern const char str_status[7];
extern const char str_issuer[7];

extern const char str_status_approving[10];
extern const char str_status_reapproving[12];
extern const char str_status_activated[10];
extern const char str_status_repudiated[11];

/**
 * strings defined in libouistiti
 */
extern const char str_contenttype[13];
extern const char str_contentlength[15];

/**
 * strings defined in libouiutils
 */
extern const char str_mime_location[9];
extern const char str_mime_textplain[11];
extern const char str_mime_texthtml[10];
extern const char str_mime_textcss[9];
extern const char str_mime_textjson[10];
extern const char str_mime_imagepng[10];
extern const char str_mime_imagejpeg[11];
extern const char str_mime_applicationjavascript[23];
extern const char str_mime_applicationoctetstream[24];

#endif
