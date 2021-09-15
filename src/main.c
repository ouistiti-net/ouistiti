/*****************************************************************************
 * main.c: main entry file
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
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>
#include <libgen.h>
#include <sched.h>
#include <dirent.h>

#ifndef WIN32
# include <sys/socket.h>
# include <sys/types.h>
# include <unistd.h>
# include <fcntl.h>
# include <pwd.h>
# include <grp.h>
#else
# include <winsock2.h>
#endif

#include "daemonize.h"
#include "../compliant.h"
#include "ouistiti/httpserver.h"
#include "ouistiti/log.h"

#ifndef FILE_CONFIG
#define STATIC_CONFIG
#endif

#include "ouistiti.h"

#define STR(x) #x
#define PACKAGEVERSION PACKAGE_NAME "/" PACKAGE_VERSION
#define DEFAULT_CONFIGPATH SYSCONFDIR"/ouistiti.conf"

#include "mod_auth.h"

extern const char str_hostname[];

const char *auth_info(http_message_t *request, const char *key)
{
	const authsession_t *info = NULL;
	info = httpmessage_SESSION(request, "auth", NULL, 0);
	const char *value = NULL;

	if (info == NULL)
		return NULL;
	if (!strcmp(key, "user"))
		value = (const char *)info->user;
	if (!strcmp(key, "group"))
		value = (const char *)info->group;
	if (!strcmp(key, "type"))
		value = (const char *)info->type;
	if (!strcmp(key, "home"))
		value = (const char *)info->home;
	return value;
}

int auth_setowner(const char *user)
{
	int ret = EREJECT;
#ifdef HAVE_PWD
	struct passwd *pw;
	pw = getpwnam(user);
	if (pw != NULL)
	{
		uid_t uid;
		uid = getuid();
		//only "saved set-uid", "uid" and "euid" may be set
		//first step: set the "saved set-uid" (root)
		if (seteuid(uid) < 0)
			warn("not enought rights to change user");
		//second step: set the new "euid"
		else if (setegid(pw->pw_gid) < 0)
			warn("not enought rights to change group");
		else if (seteuid(pw->pw_uid) < 0)
			warn("not enought rights to change user");
		else
			ret = ESUCCESS;
	}
#else
	ret = ESUCCESS;
#endif
	return ret;
}

static module_list_t *g_modules = NULL;

typedef struct mod_s
{
	void *obj;
	const module_t *ops;
} mod_t;

#define MAX_MODULES 16
struct server_s
{
	serverconfig_t *config;
	http_server_t *server;
	mod_t modules[MAX_MODULES + MAX_SERVERS];

	struct server_s *next;
	unsigned int id;
};

static int main_exec(int rootfd,  const char *scriptpath)
{
        pid_t pid = fork();
        if (pid == 0)
        {

                char * const argv[2] = { (char *)scriptpath, NULL };
                setlinebuf(stdout);
                sched_yield();

                char * const env[1] = { NULL };
#ifdef USE_EXECVEAT
                execveat(rootfd, scriptpath, argv, env);
#elif defined(USE_EXECVE)
				fchdir(rootfd);
                execve(scriptpath, argv, env);
#else
                int scriptfd = openat(rootfd, scriptpath, O_PATH);
                close(rootfd);
                fexecve(scriptfd, argv, env);
#endif
                err("cgi error: %s", strerror(errno));
                exit(0);
	}
	return pid;
}

static int main_initat(int rootfd, const char *path)
{
	struct stat filestat = {0};
	if (fstatat(rootfd, path, &filestat, 0) != 0)
		return EREJECT;
	if (S_ISDIR(filestat.st_mode))
	{
		struct dirent **namelist;
		int n;
		n = scandirat(rootfd, path, &namelist, NULL, alphasort);
		if (n == -1)
			return EREJECT;
		int newrootfd = openat(rootfd, path, O_DIRECTORY);
		while (n--)
		{
			if (namelist[n]->d_name[0] != '.')
				main_initat(newrootfd, namelist[n]->d_name);
			free(namelist[n]);
		}
		close(newrootfd);

	}
	else if (faccessat(rootfd, path, X_OK, 0) == 0)
	{
		main_exec(rootfd, path);
	}
	int n = faccessat(rootfd, path, X_OK, 0);

	return ESUCCESS;
}

void display_configuration(const char *configfile, const char *pidfile)
{
	fprintf(stdout, "sysconfdir=\""STR(SYSCONFDIR) "\"\n");
	fprintf(stdout, "prefix=\"" STR(PREFIX) "\"\n");
	fprintf(stdout, "libdir=\"" STR(LIBDIR) "\"\n");
	fprintf(stdout, "pkglibdir=\"" STR(PKGLIBDIR) "\"\n");
	fprintf(stdout, "datadir=\"" STR(DATADIR) "\"\n");
	char *path;
	path = realpath(configfile, NULL);
	if (path != NULL)
	{
		fprintf(stdout, "configfile=\"%s\"\n", path);
		free(path);
	}
	path = NULL;
	if (pidfile != NULL)
		path = realpath(pidfile, NULL);
	if (path != NULL)
	{
		fprintf(stdout, "pidfile=\"%s\"\n", path);
		free(path);
	}
	fprintf(stdout, "hostname=\"%s\"\n", str_hostname);
};

void display_help(char * const *argv)
{
	fprintf(stderr, PACKAGE_NAME" "PACKAGE_VERSION" build: "__DATE__" "__TIME__"\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "%s [-h][-V][-f <configfile>]\n", argv[0]);
	fprintf(stderr, "\t-h \t\tshow this help and exit\n");
	fprintf(stderr, "\t-V \t\treturn the version and exit\n");
	fprintf(stderr, "\t-f <configfile>\tset the configuration file path\n");
	fprintf(stderr, "\t-M <modules_path>\tset the path to modules\n");
	fprintf(stderr, "\t-p <pidfile>\tset the file path to save the pid\n");
	fprintf(stderr, "\t-D \t\tto daemonize the server\n");
	fprintf(stderr, "\t-K \t\tto kill other instances of the server\n");
	fprintf(stderr, "\t-s <server num>\tselect a server into the configuration file\n");
}

static server_t *first = NULL;
static char run = 0;
static int g_default_port = 80;
#ifdef HAVE_SIGACTION
static void handler(int sig, siginfo_t *UNUSED(si), void *UNUSED(arg))
#else
static void handler(int sig)
#endif
{
	run = 'q';
}

http_server_t *ouistiti_httpserver(server_t *server)
{
	return server->server;
}

int ouistiti_issecure(server_t *server)
{
	const char *secure = httpserver_INFO(server->server, "secure");
	return !!strcmp(secure, "true");
}

static int ouistiti_loadmodule(server_t *server, const module_t *module, configure_t configure, void *parser)
{
	int i = 0;
	mod_t *mod = &server->modules[i];
	while (i < MAX_MODULES && mod->obj != NULL)
		mod = &server->modules[++i];
	if (i == MAX_MODULES)
		return EREJECT;

	if (module->version & MODULE_VERSION_DEPRECATED)
	{
		warn("module %s deprecated", module->name);
		return EREJECT;
	}
	if (module->version < MODULE_VERSION_CURRENT)
	{
		warn("module %s old. Please check", module->name);
	}
	void *config = NULL;
	if (module->configure != NULL)
		config = module->configure(parser, server);
	else if (configure != NULL)
		config = configure(parser, module, server);
	mod->obj = module->create(server->server, config);
	mod->ops = module;
	return (mod->obj != NULL)?ESUCCESS:EREJECT;
}

static int ouistiti_setmodules(server_t *server, configure_t configure, void *parser)
{
	const module_list_t *iterator = g_modules;
	while (iterator != NULL)
	{
		ouistiti_loadmodule(server, iterator->module, configure, parser);
		iterator = iterator->next;
	}
	return 0;
}

void ouistiti_registermodule(const module_t *module)
{
	module_list_t *iterator = g_modules;
	while (iterator != NULL)
	{
		if (!strcmp(iterator->module->name, module->name))
		{
			warn("module %s loaded twice", module->name);
			return;
		}
		iterator = iterator->next;
	}
	module_list_t *new = calloc(1, sizeof(*new));
	new->module = module;
	new->next = g_modules;
	g_modules = new;
	dbg("module %s regitered", module->name);
}

const module_list_t *ouistiti_modules(server_t *server)
{
	return g_modules;
}

static void __ouistiti_freemodule()
{
	module_list_t *iterator = g_modules;
	while (iterator != NULL)
	{
		module_list_t *next = iterator->next;
		free(iterator);
		iterator = next;
	}
}

static server_t *ouistiti_loadserver(serverconfig_t *config, int id)
{
	if (first == NULL && id == -1)
		id = 0;

	if (first != NULL && first->id == MAX_SERVERS)
		return NULL;

	if (config->server->port == 0)
		config->server->port = g_default_port;
	http_server_t *httpserver = httpserver_create(config->server);
	if (httpserver == NULL)
		return NULL;

	server_t *server = NULL;
	server = calloc(1, sizeof(*server));

	server->server = httpserver;
	server->config = config;
	if (id == -1)
		server->id = first->id + 1;
	else
		server->id = id;
	ouistiti_setmodules(server, NULL, config->modulesconfig);

	return server;
}

#ifdef STATIC_CONFIG
static ouistiticonfig_t g_ouistiti_config =
{
	.user = "www-data",
	.pidfile = "/var/run/ouistiti.pid",
	.init_d = SYSCONFDIR"/init.d",
	.servers = {
		&(serverconfig_t){
			.server = &(http_server_config_t){
				.port = 0,
				.chunksize = DEFAULT_CHUNKSIZE,
				.maxclients = DEFAULT_MAXCLIENTS,
				.version = HTTP11,
			}
		},
		NULL
	},
};

static void *_config_modules(void *data, const char *name, server_t *server)
{
	return NULL;
}

ouistiticonfig_t *ouistiticonfig_create(const char *filepath)
{
	return &g_ouistiti_config;
}
#endif

static int main_run(server_t *first)
{
	server_t *server = first;
	/**
	 * connection must be after the owner change
	 */
	while (server != NULL)
	{
		httpserver_connect(server->server);
		server = server->next;
	}

	while(run != 'q')
	{
		if (first == NULL || first->server == NULL || httpserver_run(first->server) == ESUCCESS)
			break;
	}

	return 0;
}

void main_destroy(server_t *first)
{
	server_t *server = first;
	server = first;

	while (server != NULL)
	{
		server_t *next = server->next;
		int j = 0;
		while (server->modules[j].obj)
		{
			if (server->modules[j].ops->destroy)
				server->modules[j].ops->destroy(server->modules[j].obj);
			j++;
		}
		httpserver_disconnect(server->server);
		httpserver_destroy(server->server);
		free(server);
		server = next;
	}
	__ouistiti_freemodule();
}

static server_t *ouistiti_loadservers(ouistiticonfig_t *ouistiticonfig, int serverid)
{
	server_t *first = NULL;
	int id = 0;
	for (int i = 0; i < MAX_SERVERS; i++)
	{
		if (serverid != -1 && i != serverid)
			continue;

		if (ouistiticonfig->config[i] != NULL)
		{
			server_t *server = ouistiti_loadserver(ouistiticonfig->config[i], id);
			id += 1;
			if (server != NULL)
			{
				server->next = first;
				first = server;
			}
		}
	}
	return first;
}

static int ouistiti_kill(const char *configfile, const char *pidfile)
{
	ouistiticonfig_t *ouistiticonfig = NULL;
	if (pidfile == NULL)
	{
		ouistiticonfig = ouistiticonfig_create(configfile);
		if (ouistiticonfig && ouistiticonfig->pidfile)
			pidfile = ouistiticonfig->pidfile;
	}
	killdaemon(pidfile);
	if (ouistiticonfig)
		ouistiticonfig_destroy(ouistiticonfig);
	main_destroy(first);
	return 0;
}

#define DAEMONIZE 0x01
#define KILLDAEMON 0x02
#define CONFIGURATION 0x04
static char servername[] = PACKAGEVERSION;
int main(int argc, char * const *argv)
{
	const char *configfile = DEFAULT_CONFIGPATH;
	const char *pidfile = NULL;
	const char *workingdir = NULL;
	int mode = 0;
	int serverid = -1;
	const char *pkglib = PKGLIBDIR;

//	setlinebuf /( stdout /);
//	setlinebuf /( stderr /);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	httpserver_software = servername;

#ifdef HAVE_GETOPT
	int opt;
	do
	{
		opt = getopt(argc, argv, "s:f:p:P:hDKCVM:W:");
		switch (opt)
		{
			case 's':
				serverid = atoi(optarg) - 1;
			break;
			case 'f':
				configfile = optarg;
			break;
			case 'p':
				pidfile = optarg;
			break;
			case 'M':
				pkglib = optarg;
			break;
			case 'P':
				g_default_port = atoi(optarg);
			break;
			case 'h':
				display_help(argv);
			return -1;
			case 'V':
				printf("%s\n",PACKAGEVERSION);
			return 1;
			case 'D':
				mode |= DAEMONIZE;
			break;
			case 'K':
				mode |= KILLDAEMON;
			break;
			case 'C':
				mode |= CONFIGURATION;
			break;
			case 'W':
				 workingdir = optarg;
			break;
			default:
			break;
		}
	} while(opt != -1);
#endif

	if (mode & KILLDAEMON)
	{
		return ouistiti_kill(configfile, pidfile);
	}

	if (workingdir != NULL && chdir(workingdir) != 0)
	{
		err("%s directory is not accessible", workingdir);
		return 1;
	}

	ouistiti_initmodules(pkglib);
#ifdef MODULES
	const char *modules_path = getenv("OUISTITI_MODULES_PATH");
	if (modules_path != NULL)
		ouistiti_initmodules(modules_path);
#endif

	ouistiticonfig_t *ouistiticonfig = NULL;
	ouistiticonfig = ouistiticonfig_create(configfile);
	if (ouistiticonfig == NULL)
	{
		err("Ouistiti configuration not found !!!");
		return 1;
	}

	if (pidfile == NULL && ouistiticonfig->pidfile)
		pidfile = ouistiticonfig->pidfile;

	if (mode & CONFIGURATION)
	{
		display_configuration(configfile, pidfile);
		return 0;
	}

	if (ouistiticonfig->init_d != NULL)
	{
		int rootfd = AT_FDCWD;
		main_initat(rootfd, ouistiticonfig->init_d);
	}

	if ((mode & DAEMONIZE) && daemonize(pidfile) == -1)
	{
		/**
		 * if main is destroyed, it close the server socket here
		 * and the true process is not able to receive any connection
		 */
		// main_destroy /( first /) /;
		return 0;
	}

	if (ouistiticonfig == NULL)
	{
		return -1;
	}

	first = ouistiti_loadservers(ouistiticonfig, serverid);

#ifdef HAVE_SIGACTION
	struct sigaction action;
	action.sa_flags = SA_SIGINFO;
	sigemptyset(&action.sa_mask);
	action.sa_sigaction = handler;
	sigaction(SIGTERM, &action, NULL);
	sigaction(SIGINT, &action, NULL);

	struct sigaction unaction;
	unaction.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &action, NULL);
#else
	signal(SIGTERM, handler);
	signal(SIGINT, handler);

	signal(SIGPIPE, SIG_IGN);
#endif

	if (auth_setowner(ouistiticonfig->user) == EREJECT)
		err("Error: user %s not found\n", ouistiticonfig->user);

	main_run(first);

	killdaemon(pidfile);
	main_destroy(first);
	ouistiticonfig_destroy(ouistiticonfig);
	warn("good bye");
	return 0;
}
