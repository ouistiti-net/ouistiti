modules-$(MODULES)+=mod_authmngt
slib-$(STATIC)+=mod_authmngt
mod_authmngt_SOURCES+=mod_authmngt.c
mod_authmngt_SOURCES-$(AUTHZ_SQLITE)+=authmngt_sqlite.c
mod_authmngt_CFLAGS+=-I../src
mod_authmngt_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
mod_authmngt_LDFLAGS+=$(LIBHTTPSERVER_LDFLAGS)
mod_authmngt_LIBS+=$(LIBHTTPSERVER_NAME)
mod_authmngt_LIBS+=ouiutils
mod_authmngt_LIBS+=ouihash
mod_authmngt_LIBRARY+=sqlite3

# mod_authmngt depends on mod_auth
#mod_authmngt_SOURCES-$(AUTHZ_SQLITE)+=authz_sqlite.c

mod_authmngt_CFLAGS-$(DEBUG)+=-g -DDEBUG
