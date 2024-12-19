/*****************************************************************************
 * stringscollection.c: list of standard strings for modules
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
const char str_servername[9] = "ouistiti";

const char str_https[6] = "https";

/// defined into libouistiti
//const char str_get[] = "GET";
//const char str_post[] = "POST";
//const char str_head[] = "HEAD";
const char str_put[] = "PUT";
const char str_delete[] = "DELETE";
const char str_options[] = "OPTIONS";

const char str_authenticate[] = "WWW-Authenticate";
const char str_authorization[] = "Authorization";
const char str_cachecontrol[] = "Cache-Control";
const char str_xtoken[] = "X-Auth-Token";
const char str_xuser[] = "X-Remote-User";
const char str_xgroup[] = "X-Remote-Group";
const char str_xhome[] = "X-Remote-Home";
const char str_upgrade_insec_req[] = "Upgrade-Insecure-Requests";
const char str_upgrade[] = "Upgrade";
const char str_websocket[] = "websocket";
const char str_sec_ws_protocol[] = "Sec-WebSocket-Protocol";
const char str_sec_ws_accept[] = "Sec-WebSocket-Accept";
const char str_sec_ws_key[] = "Sec-WebSocket-Key";
const char str_date[] = "Date";
const char str_authorization_code[] = "code";
const char str_access_token[] = "access_token";
const char str_state[] = "session_state";
const char str_expires[] = "expires";

const char str_multipart_replace[] = "multipart/x-mixed-replace";

const char str_boundary[] = "FRAME";

const char str_token[] = "token";
const char str_anonymous[] = "anonymous";
const char str_user[] = "user";
const char str_group[] = "group";
const char str_home[] = "home";
const char str_status[] = "status";
const char str_issuer[] = "issuer";

const char str_status_approving[] = "approving";
const char str_status_reapproving[] = "reapproving";
const char str_status_activated[] = "activated";
const char str_status_repudiated[] = "repudiated";
