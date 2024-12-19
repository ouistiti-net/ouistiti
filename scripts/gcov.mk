GCOV?=gcov --relative-only
LCOV?=lcov
GENHTML?=genhtml
TARGETGCOV:=$(TARGETPREFIX)$(GCOV)

ifeq ($(G),1)
INTERN_CFLAGS+=--coverage -fprofile-arcs -ftest-coverage
INTERN_LDFLAGS+=--coverage -fprofile-arcs -ftest-coverage
INTERN_LIBS+=gcov
O:=0
endif

reportdir?=$(builddir)report/
#gcov-target:=$(patsubst %.o,%.c.gcov,$(sort $(foreach t, $(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y),$($(t)_GENERATED) $(addprefix $(builddir)$(cwdir),$($(t)-objs)))))
gcov-target:=$(patsubst %.o,%.c.gcov,$(objs-target))
gcda-target:=$(patsubst %.o,%.gcda,$(sort $(foreach t, $(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y),$($(t)_GENERATED) $(addprefix $(builddir)$(cwdir),$($(t)-objs)))))
gcno-target:=$(patsubst %.o,%.gcno,$(sort $(foreach t, $(slib-y) $(lib-y) $(bin-y) $(sbin-y) $(modules-y),$($(t)_GENERATED) $(addprefix $(builddir)$(cwdir),$($(t)-objs)))))
clean-target+=$(gcov-target) $(gcda-target) $(gcno-target)

_gcov: action:=_gcov
_gcov: build:=$(action) -f $(makemore) file
_gcov: _info $(subdir-target) $(if $(findstring y,$(GCOV_DISABLED)),,$(gcov-target))
	@:

gcov: action:=_gcov
gcov: build:=$(action) -f $(makemore) file
gcov: default_action ;

quiet_cmd_cc_gcov_c=GCOV $*
 cmd_cc_gcov_c=$(TARGETGCOV) $(GCOV_OPTIONS) -p $(notdir $<) -t > $@;
quiet_cmd_lcov=LCOV
 cmd_lcov=$(LCOV) --directory $(builddir) --capture --output-file $@
quiet_cmd_genhtml=GENHTML $@
 cmd_genhtml=$(GENHTML) $< --output-directory $(dir $@)

$(objdir)%.c.gcov: GCOV_OPTIONS=-o $(dir $@) -s $(dir $<)
$(objdir)%.c.gcov:$(srcdir)%.c $(wildcard $(objdir)%.gcno $(objdir)%.gcda)
	$(Q)$(call cmd,cc_gcov_c)

$(objdir)%.c.gcov: GCOV_OPTIONS=-o $(dir $@) -s $(dir $<)
$(objdir)%.c.gcov:$(srcdir)%.cpp  $(wildcard $(objdir)%.gcno $(objdir)%.gcda)
	$(Q)$(call cmd,cc_gcov_c)

# for generated files
$(objdir)%.c.gcov: GCOV_OPTIONS=-o $(dir $@) -s $(dir $<)
$(objdir)%.c.gcov:$(objdir)%.c $(wildcard $(objdir)%.gcno $(objdir)%.gcda)
	$(Q)$(call cmd,cc_gcov_c)

$(objdir)%.c.gcov: GCOV_OPTIONS=-o $(dir $@) -s $(dir $<)
$(objdir)%.c.gcov:$(objdir)%.cpp  $(wildcard $(objdir)%.gcno $(objdir)%.gcda)
	$(Q)$(call cmd,cc_gcov_c)

gcovhtml: $(reportdir) $(reportdir)index.html

$(reportdir):
	$(Q)$(call cmd,mkdir,$@)

$(reportdir)gcov.info:
	$(Q)$(call cmd,lcov)

$(reportdir)index.html: $(reportdir)gcov.info
	$(Q)$(call cmd,genhtml)
