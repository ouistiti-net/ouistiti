/*****************************************************************************
 * config.c: configuration file parser
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
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <dirent.h>

#include <libconfig.h>

#include "ouistiti/httpserver.h"
#include "ouistiti/utils.h"

#include "ouistiti/log.h"
#include "ouistiti.h"

extern char str_hostname[HOST_NAME_MAX + 7];

static char *logfile = NULL;
static int logfd = 0;

typedef void (*_parsercb_t)(void *arg, const char *option, size_t length);

static void config_mimes(const config_setting_t *configmimes)
{
	if (configmimes == NULL)
		return;

	int count = config_setting_length(configmimes);
	for (int i = 0; i < count; i++)
	{
		char *ext = NULL;
		char *mime = NULL;
		const config_setting_t *iterator = config_setting_get_elem(configmimes, i);
		if (iterator)
		{
			config_setting_lookup_string(iterator, "ext", (const char **)&ext);
			config_setting_lookup_string(iterator, "mime", (const char **)&mime);
			if (mime != NULL && ext != NULL)
			{
				utils_addmime(ext, mime);
			}
		}
	}
}

static serverconfig_t *config_server(config_setting_t *iterator, config_t *configfile)
{
	serverconfig_t *config = calloc(1, sizeof(*config));

	config->server = calloc(1, sizeof(*config->server));
	char *hostname = NULL;
	config_setting_lookup_string(iterator, "hostname", (const char **)&hostname);
	if (hostname && strchr(hostname, '.') == NULL)
	{
		err("hostname must contain the domain");
	}
	else if (hostname == NULL)
	{
		hostname = str_hostname;
	}
	warn("hostname %s", hostname);
	config->server->hostname = hostname;
	config->server->port = 80;
	config_setting_lookup_int(iterator, "port", &config->server->port);
	config_setting_lookup_string(iterator, "addr", (const char **)&config->server->addr);
	config_setting_lookup_string(iterator, "service", &config->server->service);
	config_setting_lookup_int(iterator, "keepalivetimeout", &config->server->keepalive);
	config->server->chunksize = HTTPMESSAGE_CHUNKSIZE;
	config_setting_lookup_int(iterator, "chunksize", &config->server->chunksize);
	config->server->maxclients = DEFAULT_MAXCLIENTS;
	config_setting_lookup_int(iterator, "maxclients", &config->server->maxclients);
	config->server->version = HTTP11;
	const char *version = NULL;
	config_setting_lookup_string(iterator, "version", &version);
	if (version)
	{
		const char *version_test = NULL;
		httpserver_version(0, &version_test);
		for (int i = 0; version_test != NULL; i++)
		{
			if (!strcmp(version_test,  version))
			{
				config->server->version = i;
				config->server->versionstr = version_test;
				break;
			}
			httpserver_version(i + 1, &version_test);
		}
	}
	config_setting_lookup_string(iterator, "root", &config->root);
	config->modulesconfig = iterator;
	config->configfile = configfile;
	return config;
}

static int ouistiticonfig_mergeserver(serverconfig_t *main, serverconfig_t *new)
{
	return EREJECT;
}

static int ouistiticonfig_appendserver(serverconfig_t *new, ouistiticonfig_t *ouistiticonfig)
{
	int ret = EREJECT;
	int nservers = ouistiticonfig->nservers;

	if (nservers < MAX_SERVERS)
	{
		ouistiticonfig->config[nservers] = new;
		ouistiticonfig->nservers++;
		ret = ESUCCESS;
	}
	return ret;
}

static int ouistiticonfig_checkserver(serverconfig_t *new, ouistiticonfig_t *ouistiticonfig)
{
	int nservers = ouistiticonfig->nservers;

	for (int i = 0; i < nservers; i++)
	{
		serverconfig_t *it = ouistiticonfig->config[i];
		if (new->server->port == it->server->port)
		{
			return ouistiticonfig_mergeserver(it, new);
		}
	}
	return ouistiticonfig_appendserver(new, ouistiticonfig);
}

static void ouistiticonfig_servers(config_t *configfile, ouistiticonfig_t *ouistiticonfig)
{
	const config_setting_t *configservers = config_lookup(configfile, "servers");
	if (configservers == NULL)
	{
		configservers = config_lookup(configfile, "server");
	}
	if (configservers)
	{
		int count = config_setting_length(configservers);

		for (int i = 0; i < count; i++)
		{
			int ret;

			config_setting_t *iterator = config_setting_get_elem(configservers, i);
			serverconfig_t *config = config_server(iterator, configfile);
			ret = ouistiticonfig_checkserver(config, ouistiticonfig);
			if (ret == EREJECT)
			{
				free(config->server);
				free(config);
			}
		}
	}
}

static void ouistiticonfig_subconfigfile(const char *filepath, ouistiticonfig_t *ouistiticonfig)
{
	config_t *configfile = calloc(1, sizeof(*configfile));
	int ret = config_read_file(configfile, filepath);
	if (ret != CONFIG_TRUE)
	{
		err("config: %s %s", filepath, config_error_text(configfile));
		free(configfile);
		return;
	}
	ouistiticonfig_servers(configfile, ouistiticonfig);
}

ouistiticonfig_t *ouistiticonfig_create(const char *filepath)
{
	int ret;

	char hostname[HOST_NAME_MAX];
	gethostname(hostname, HOST_NAME_MAX);
	snprintf(str_hostname, sizeof(str_hostname), "%s.local", hostname);

	if (access(filepath, R_OK))
	{
		err("config file: %s not found", filepath);
		return NULL;
	}
	config_t *configfile = calloc(1, sizeof(*configfile));
	config_init(configfile);
	dbg("config file: %s", filepath);
	ret = config_read_file(configfile, filepath);
	if (ret != CONFIG_TRUE)
	{
		err("config: %s %s", filepath, config_error_text(configfile));
		free(configfile);
		return NULL;
	}
	ouistiticonfig_t *ouistiticonfig = calloc(1, sizeof(*ouistiticonfig));
	ouistiticonfig->configfile = configfile;

	config_lookup_string(configfile, str_user, (const char **)&ouistiticonfig->user);
	config_lookup_string(configfile, "log-file", (const char **)&logfile);
	if (logfile != NULL && logfile[0] != '\0')
	{
		logfd = open(logfile, O_WRONLY | O_CREAT | O_TRUNC, 00644);
		if (logfd > 0)
		{
			dup2(logfd, 1);
			dup2(logfd, 2);
			close(logfd);
		}
		else
			err("log file error %s", strerror(errno));
	}
	config_lookup_string(configfile, "init_d", (const char **)&ouistiticonfig->init_d);
	const config_setting_t *configmimes = config_lookup(configfile, "mimetypes");
	config_mimes(configmimes);

	ouistiticonfig_servers(configfile, ouistiticonfig);
	char *configd = NULL;
	config_lookup_string(configfile, "config_d", (const char **)&configd);
	DIR *configdir = NULL;
	if (configd != NULL)
		configdir = opendir(configd);
	if (configdir != NULL)
	{
		struct dirent *entry = readdir(configdir);
		while (entry != NULL)
		{
			if (entry->d_type == DT_REG && !utils_searchexp(entry->d_name, "*.conf$", NULL))
			{
				char path[PATH_MAX] = {0};
				snprintf(path, PATH_MAX - 1, "%s/%s",configd, entry->d_name);
				ouistiticonfig_subconfigfile(path, ouistiticonfig);
			}
			entry = readdir(configdir);
		}
		closedir(configdir);
	}
	else if (configd != NULL)
	{
		struct stat filestat;
		int ret = stat(configd, &filestat);
		if (!ret && S_ISREG(filestat.st_mode))
			ouistiticonfig_subconfigfile(configd, ouistiticonfig);
	}

	return ouistiticonfig;
}

void ouistiticonfig_destroy(ouistiticonfig_t *ouistiticonfig)
{
	if (logfd > 0)
		close(logfd);
	void *lastconfig = NULL;
	for (int i = 0; i < MAX_SERVERS; i++)
	{
		if (ouistiticonfig->config[i] != NULL)
		{
			if ((ouistiticonfig->config[i]->configfile != ouistiticonfig->configfile) &&
				(ouistiticonfig->config[i]->configfile != lastconfig))
			{
				lastconfig = ouistiticonfig->config[i]->configfile;
				config_destroy((config_t *)ouistiticonfig->config[i]->configfile);
				free(ouistiticonfig->config[i]->configfile);
			}
			free(ouistiticonfig->config[i]->server);
			free(ouistiticonfig->config[i]);
		}
	}
	config_destroy((config_t *)ouistiticonfig->configfile);
	free(ouistiticonfig->configfile);
	free(ouistiticonfig);
}
