modules-$(MODULES)+=mod_signature
slib-$(STATIC)+=mod_signature
mod_signature_SOURCES+=mod_signature.c
mod_signature_CFLAGS+=$(LIBHTTPSERVER_CFLAGS)
mod_signature_LDFLAGS+=$(LIBHTTPSERVER_LDFLAGS)
mod_signature_LIBS+=$(LIBHTTPSERVER_NAME)
mod_signature_LIBS+=ouihash
mod_signature_CFLAGS+=-I$(srcdir)src

mod_signature_CFLAGS-$(DEBUG)+=-g -DDEBUG
