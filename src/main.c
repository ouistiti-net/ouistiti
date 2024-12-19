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
#include <limits.h>
#ifdef BACKTRACE
#include <execinfo.h> // for backtrace
#endif

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

char str_hostname[HOST_NAME_MAX + 7];

#define MAX_STRING 256

size_t string_length(const string_t *str)
{
	if (str->data && str->length == (size_t) -1)
		((string_t*)str)->length = strnlen(str->data, MAX_STRING);
	return str->length;
}

int string_store(string_t *str, const char *pointer, size_t length)
{
	str->data = pointer;
	/// set length and check if value is -1
	str->length = length;
	str->length = string_length(str);
	str->size = str->length + 1;
	if (str->data == NULL)
	{
		str->length = 0;
		str->size = 0;
	}
	return ESUCCESS;
}

int string_cmp(const string_t *str, const char *cmp, size_t length)
{
	if (cmp == NULL)
		return -1;
	if ((length != (size_t) -1) && (length != str->length))
		return (length - str->length);
	return strncasecmp(str->data, cmp, str->length);
}

int string_contain(const string_t *str, const char *cmp, size_t length, const char sep)
{
	int ret = -1;
	if (cmp == NULL)
		return -1;
	if (length == (size_t) -1)
		length = strnlen(cmp, str->length);
	const char *offset = str->data;
	while (offset && offset[0] != '\0')
	{
		if (!strncasecmp(offset, cmp, length))
		{
			ret = 0;
			break;
		}
		offset = strchr(offset, sep);
		if (offset)
			offset++;
	}
	return ret;
}

int string_empty(const string_t *str)
{
	return ! (str->data != NULL && str->data[0] != '\0' && str->length > 0);
}

int string_cpy(string_t *str, const char *source, size_t length)
{
	if (str->data == NULL)
		return EREJECT;
	if ((length == (size_t) -1) || (length > INT_MAX))
		str->length = snprintf((char *)str->data, str->size, "%s", source);
	else
		str->length = snprintf((char *)str->data, str->size, "%.*s", (int)length, source);
	return str->length;
}

const char *string_toc(const string_t *str)
{
	return str->data;
}

int ouimessage_REQUEST(http_message_t *message, const char *key, string_t *value)
{
	const char *data = NULL;
	size_t datalen = httpmessage_REQUEST2(message, key, &data);
	if (data == NULL)
		return EREJECT;
	string_store(value, data, datalen);
	return ESUCCESS;
}

int ouimessage_SESSION(http_message_t *message, const char *key, string_t *value)
{
	void *data = NULL;
	size_t datalen = httpmessage_SESSION2(message, key, &data);
	if (data == NULL)
		return EREJECT;
	string_store(value, data, datalen);
	return ESUCCESS;
}

int ouimessage_parameter(http_message_t *message, const char *key, string_t *value)
{
	const char *data = NULL;
	size_t datalen = httpmessage_parameter(message, key, &data);
	if (data == NULL)
		return EREJECT;
	string_store(value, data, datalen);
	return ESUCCESS;
}
/******************************************************************************/
const char *auth_info(http_message_t *request, const char *key, size_t keylen)
{
	return httpclient_session(httpmessage_client(request), key, keylen, NULL, -1);
}

size_t auth_info2(http_message_t *request, const char *key, const char **value)
{
	return httpmessage_SESSION2(request, key, (void **)value);
}

int ouistiti_setprocessowner(const char *user)
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

#define MAX_MODULES 16
struct server_s
{
	serverconfig_t *config;
	http_server_t *server;
	mod_t *modules;

	struct server_s *next;
	unsigned int id;
};

const char *actions[] = {
	"start",
	"stop"
};
static int main_exec(int rootfd,  const char *scriptpath, int stop)
{
        pid_t pid = fork();
        if (pid == 0)
        {

                char * const argv[3] = { (char *)scriptpath, (char *)actions[stop], NULL };
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

static int main_initat(int rootfd, const char *path, int action)
{
	struct stat filestat = {0};
	if (fstatat(rootfd, path, &filestat, 0) != 0)
	{
		err("main: file %s not found %m", path);
		return EREJECT;
	}
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
			{
				main_initat(newrootfd, namelist[n]->d_name, action);
			}
			free(namelist[n]);
		}
		free(namelist);
		close(newrootfd);
	}
	else if (faccessat(rootfd, path, X_OK, 0) == 0)
	{
		warn("main: %s %s script", actions[action], path);
		main_exec(rootfd, path, action);
	}
	else
		err("main: %s is not executable", path);

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
	fprintf(stderr, "\t-W <directory>\tset the working directory as chroot\n");
}

static int _ouistiti_chown(int fd, const char *owner)
{
#ifdef HAVE_PWD
	struct passwd *pw;
	pw = getpwnam(owner);
	if (pw != NULL)
	{
		return fchown(fd, pw->pw_uid, pw->pw_gid);
	}
#endif
	return -1;
}
static const char *g_logfile = NULL;
static int g_logfd = 0;
size_t g_logmax = 1024 * 1024;
int ouistiti_setlogfile(const char *logfile, size_t logmax, const char *owner)
{
	if (g_logfile != NULL)
		logfile = g_logfile;
	if (logfile != NULL && logfile[0] != '\0' && logfile[0] != '-')
	{
		const char *logmaxenv = getenv("LOG_MAXFILESIZE");
		if (logmaxenv)
			logmax = strtoul(logmaxenv, NULL, 10);
		if (logmax)
			g_logmax = logmax;
		g_logfile = logfile;
		g_logfd = open(logfile, O_WRONLY | O_CREAT | O_TRUNC, 00660);
		if (g_logfd > 0)
		{
			if (owner && _ouistiti_chown(g_logfd, owner) == -1)
				warn("main: impossible to change logfile owner");
			dup2(g_logfd, 1);
			dup2(g_logfd, 2);
			close(g_logfd);
		}
		else
			err("log file error %s", strerror(errno));
	}
	else
		g_logfile = NULL;
	return (g_logfd > 0);
}

#undef BACKTRACE
static server_t *g_first = NULL;
static char run = 0;
static int g_default_port = 80;
#ifdef HAVE_SIGACTION
static void handler(int sig, siginfo_t *UNUSED(si), void *UNUSED(arg))
#else
static void handler(int sig)
#endif
{
	err("main: signal %d", sig);
	if (sig == SIGSEGV)
	{
#ifdef BACKTRACE
		void *array[10];
		size_t size;

		// get void*'s for all entries on the stack
		size = backtrace(array, 10);

		// print out all the frames to stderr
		backtrace_symbols_fd(array, size, STDERR_FILENO);
#endif
#ifdef DEBUG
		err("main: pausing");
		pause();
#else
		exit(1);
#endif
	}
	if (sig != SIGPIPE)
		run = 'q';
}

http_server_t *ouistiti_httpserver(server_t *server)
{
	return server->server;
}

serverconfig_t *ouistiti_serverconfig(server_t *server)
{
	return server->config;
}

int ouistiti_issecure(server_t *server)
{
	const char *secure = httpserver_INFO(server->server, "secure");
	return !strcmp(secure, "true");
}

static int ouistiti_loadmodule(server_t *server, const module_t *module, configure_t configure, void *parser)
{
	int i = 0;
	mod_t *mod = server->modules;
	warn("module %s regitering...", module->name);
	for (;i < MAX_MODULES && mod != NULL; i++)
	{
		if (! strcmp(mod->ops->name, module->name))
			warn(" already set");
		mod = mod->next;
	}
	if (i == MAX_MODULES)
		return EREJECT;

	if (module->version & MODULE_VERSION_DEPRECATED)
	{
		warn(" deprecated");
		return EREJECT;
	}
	if (module->version < MODULE_VERSION_CURRENT)
	{
		warn(" old. Please check");
	}
	int ret = ECONTINUE;
	i = 0;
	while (ret == ECONTINUE)
	{
		void *config = NULL;
		if (module->configure != NULL && module->version == 0x00)
		{
			config = ((module_configure_v0_t)module->configure)(parser, server);
			ret = ESUCCESS;
		}
		else if (module->configure != NULL && module->version == 0x01)
			ret = module->configure(parser, server, i++, &config);
		else if (configure != NULL)
			config = configure(parser, module, server);
		else
			ret = ESUCCESS;
		void *obj = NULL;
		// check to case if the configure is deprecated and returns handle
		if (ret == ECONTINUE || ret == ESUCCESS)
		{
			obj = module->create(server->server, config);
		}
		if (obj)
		{
			mod = calloc(1, sizeof(*mod));
			dbg("main: %s configurated", module->name);
			mod->obj = obj;
			mod->ops = module;
			mod->next = server->modules;
			server->modules = mod;
		}
	}
	return ret;
}

static int ouistiti_setmodules(server_t *server, configure_t configure, void *parser)
{
	for (const module_list_t *iterator = g_modules; iterator != NULL; iterator = iterator->next)
	{
		if (ouistiti_loadmodule(server, iterator->module, configure, parser) == ESUCCESS)
		{
			warn(" done");
		}
	}
	return 0;
}

void ouistiti_registermodule(const module_t *module, void *dh)
{
	for (const module_list_t *iterator = g_modules; iterator != NULL; iterator = iterator->next)
	{
		if (!strcmp(iterator->module->name, module->name))
		{
			warn("module %s loaded twice", module->name);
			return;
		}
	}
	module_list_t *new = calloc(1, sizeof(*new));
	new->module = module;
	new->next = g_modules;
	new->dh = dh;
	g_modules = new;
}

const module_list_t *ouistiti_modules(server_t *server)
{
	return g_modules;
}

static void __ouistiti_freemodule()
{
	module_list_t *next;
	for (module_list_t *iterator = g_modules; iterator != NULL; iterator = next)
	{
		ouistiti_finalizemodule(iterator->dh);
		next = iterator->next;
		free(iterator);
	}
}

static server_t *ouistiti_loadserver(serverconfig_t *config, int id)
{
	if (g_first == NULL && id == -1)
		id = 0;

	if (g_first != NULL && g_first->id == MAX_SERVERS)
		return NULL;

	if (config->server->port == 0)
		config->server->port = g_default_port;
	http_server_t *httpserver = httpserver_create(config->server);
	if (httpserver == NULL)
	{
		err("main: server  not created");
		return NULL;
	}

	server_t *server = NULL;
	server = calloc(1, sizeof(*server));

	server->server = httpserver;
	server->config = config;
	server->id = id;
	char cwd[PATH_MAX] = {0};
	if (config->root != NULL && config->root[0] != '\0' )
	{
		getcwd(cwd, PATH_MAX);
		if (chdir(config->root))
			err("main: change %s directory error !", config->root);
	}
#ifdef DEBUG
	char pwd[PATH_MAX];
	dbg("main: ouistiti running environment %s", getcwd(pwd, PATH_MAX));
	struct dirent **namelist;
	int n = scandir(".", &namelist, NULL, alphasort);
	while (n-- > 0)
	{
		dbg("\t%s", namelist[n]->d_name);
		free(namelist[n]);
	}
	free(namelist);
#endif
	ouistiti_setmodules(server, NULL, config->modulesconfig);
	if (cwd[0] && chdir(cwd))
		err("main: change directory error !");

	return server;
}

#ifdef STATIC_CONFIG
static ouistiticonfig_t g_ouistiti_config =
{
	.user = "www-data",
	.init_d = SYSCONFDIR"/init.d",
	.config = {
		&(serverconfig_t){
			.server = &(http_server_config_t){
				.port = 0,
				.chunksize = HTTPMESSAGE_CHUNKSIZE,
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
void ouistiticonfig_destroy(ouistiticonfig_t *ouistiticonfig)
{
}
#endif

static int main_run(server_t *first)
{
	/**
	 * connection must be after the owner change
	 */
	for (const server_t *server = first; server != NULL; server = server->next)
	{
		httpserver_connect(server->server);
	}

	while(run != 'q' && first != NULL && first->server != NULL)
	{
		if (httpserver_run(first->server) != ECONTINUE)
			break;
		struct stat logstat = {0};
		if (g_logfile && !stat(g_logfile, &logstat) && (logstat.st_size > g_logmax))
		{
			ouistiti_setlogfile(g_logfile, g_logmax, NULL);
			warn("main: reset logfile");
		}
	}
	return 0;
}

void main_destroy(server_t *first)
{
	server_t *next = NULL;

	for (server_t *server = first; server != NULL; server = next)
	{
		next = server->next;
		mod_t *mod = server->modules;
		while (mod)
		{
			mod_t *next = mod->next;
			dbg("main: destroy %s", mod->ops->name);
			if (mod->ops->destroy)
				mod->ops->destroy(mod->obj);
			free(mod);
			mod = next;
		}
		httpserver_disconnect(server->server);
		httpserver_destroy(server->server);
		free(server);
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
		opt = getopt(argc, argv, "s:f:p:P:hDKCVM:W:L:");
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
			case 'L':
				 g_logfile = optarg;
			break;
			default:
			break;
		}
	} while(opt != -1);
#endif

	if (mode & KILLDAEMON)
	{
		if (pidfile)
			killdaemon(pidfile);
		return 0;
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

	if (mode & CONFIGURATION)
	{
		display_configuration(configfile, pidfile);
		return 0;
	}

	if (workingdir != NULL)
	{
		if (chroot(workingdir) == 0)
		{
			warn("main: daemon run inside sandbox");
		}
		else if (chdir(workingdir) != 0)
		{
			err("%s directory is not accessible", workingdir);
			return 1;
		}
	}

	if (ouistiticonfig->init_d != NULL)
	{
		int rootfd = AT_FDCWD;
		main_initat(rootfd, ouistiticonfig->init_d, 0);
	}

	g_first = ouistiti_loadservers(ouistiticonfig, serverid);

#ifdef HAVE_SIGACTION
	struct sigaction action;
	action.sa_flags = SA_SIGINFO;
	sigemptyset(&action.sa_mask);
	action.sa_sigaction = handler;
	sigaction(SIGTERM, &action, NULL);
	sigaction(SIGINT, &action, NULL);
#ifdef BACKTRACE
	sigaction(SIGSEGV, &action, NULL);
#endif

	struct sigaction unaction;
	unaction.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &unaction, NULL);
#else
	signal(SIGTERM, handler);
	signal(SIGINT, handler);
#ifdef BACKTRACE
	signal(SIGSEGV, handler);
#endif

	signal(SIGPIPE, SIG_IGN);
#endif

	if (ouistiticonfig->user == NULL || ouistiti_setprocessowner(ouistiticonfig->user) == EREJECT)
		err("Error: user %s not found", ouistiticonfig->user);
	else
		warn("%s run as %s", argv[0], ouistiticonfig->user);

	main_run(g_first);

	killdaemon(pidfile);
	main_destroy(g_first);
	if (ouistiticonfig->init_d != NULL)
	{
		int rootfd = AT_FDCWD;
		main_initat(rootfd, ouistiticonfig->init_d, 1);
	}
	ouistiticonfig_destroy(ouistiticonfig);
	warn("good bye");
	if (g_logfd > 0)
		close(g_logfd);
	return 0;
}
