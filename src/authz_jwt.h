/*****************************************************************************
 * authz_simple.h: Check Authentication in configuration file
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

#ifndef __AUTHN_JWT_H__
#define __AUTHN_JWT_H__

#include "mod_auth.h"

#ifdef FILE_CONFIG
#include <libconfig.h>
void *authz_jwt_config(const config_setting_t *configauth);
#endif

extern authz_rules_t authz_jwt_rules;

typedef struct authz_jwt_s authz_jwt_t;

size_t authz_jwt_generatetoken(void *arg, http_message_t *request, char **token);
int authn_jwt_checktoken(const authz_token_config_t *config, const char *token);
const char *authz_jwt_get(const char *id_token, const char *key);
int authz_jwt_getinfo(const char *id_token, const char **user, const char **issuer);

#endif
