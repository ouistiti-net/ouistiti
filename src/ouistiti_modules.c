/*****************************************************************************
 * ouistiti_modules.c: modules initialisation
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
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <dirent.h>
#include <dlfcn.h>

#include "ouistiti/httpserver.h"
#include "ouistiti.h"

#define err(format, ...) fprintf(stderr, "\x1B[31m"format"\x1B[0m\n",  ##__VA_ARGS__)
#define warn(format, ...) fprintf(stderr, "\x1B[35m"format"\x1B[0m\n",  ##__VA_ARGS__)
#ifdef DEBUG
#define dbg(format, ...) fprintf(stderr, "\x1B[32m"format"\x1B[0m\n",  ##__VA_ARGS__)
#else
#define dbg(...)
#endif

static int modulefilter(const struct dirent *entry)
{
	return !strncmp(entry->d_name, "mod_", 4);
}

int ouistiti_initmodules(const char *pkglib)
{
	int i;

	int ret;
	struct dirent **namelist = NULL;
	char cwd[PATH_MAX];
	snprintf(cwd, PATH_MAX, "%s", pkglib);
	/**
	 * LD_BIND_NOW flag may break the modules loading
	 * but it is impossible to remove it to have a LAZY loading.
	 * unsetenv is useless in this case
	 */
	const char * ldnow = getenv("LD_BIND_NOW");
	if (ldnow)
	{
		err("modules loading NOW enabled");
	}
	char *it_r;
	char *iterator = strtok_r(cwd, ":", &it_r);
	while (iterator != NULL)
	{
		warn("Look for modules into %s", iterator);
		ret = scandir(iterator, &namelist, &modulefilter, alphasort);
		for (i = 0; i < ret; i++)
		{
			const char *name = namelist[i]->d_name;
			char path[PATH_MAX];
			snprintf(path, PATH_MAX, "%s/%s", iterator, name);
			if (strstr(name, ".so") == NULL)
			{
				free(namelist[i]);
				continue;
			}

			/**
			 * the path must contain a /
			 */
			void *dh = dlopen(path, RTLD_NOLOAD);

			/**
			 * the library is already loaded
			 */
			if (dh != NULL)
			{
				free(namelist[i]);
				continue;
			}
			dh = dlopen(path, RTLD_LAZY | RTLD_GLOBAL);

			if (dh != NULL)
			{
				/**
				 * module may declare "mod_info" symbol
				 * or module may use the library constructor function
				 * to register its "mod_info". But this method should
				 * not be use, because the library needs to be uses
				 * to call the constructor.
				 */
				module_t *module = dlsym(dh, "mod_info");
				if (module)
					ouistiti_registermodule(module, dh);
				else
				{
					err("%s not a module", path);
					dlclose(dh);
				}
			}
			else
			{
				err("module %s loading error: %s", name, dlerror());
			}
			free(namelist[i]);
		}
		iterator = strtok_r(NULL, ":", &it_r);
		free(namelist);
	}
	return ESUCCESS;
}

void ouistiti_finalizemodule(void *dh)
{
	dlclose(dh);
}
