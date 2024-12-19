modules-$(MODULES)+=mod_python
slib-$(STATIC)+=mod_python
mod_python_SOURCES+=mod_python.c
mod_python_SOURCES+=../src/cgi_env.c
mod_python_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
mod_python_LDFLAGS+=$(LIBHTTPSERVER_LDFLAGS)
mod_python_LIBS+=$(LIBHTTPSERVER_NAME)
mod_python_LIBRARY+=libconfig
ifneq ($(wildcard /usr/bin/python3-config),)
PYTHON3_LIBS=$(shell python3-config --embed --libs)
mod_python_LIBS+=$(patsubst -l%,%,$(PYTHON3_LIBS))
mod_python_LDFLAGS+=$(shell python3-config --embed --ldflags)
mod_python_CFLAGS+=$(shell python3-config --embed --cflags)
else
mod_python_LIBRARY+=python3
mod_python_LIBS+=python$(shell pkg-config python3 --modversion)
endif
mod_python_CFLAGS+=-I../src
mod_python_LIBS+=ouiutils

mod_python_CFLAGS-$(DEBUG)+=-g -DDEBUG
