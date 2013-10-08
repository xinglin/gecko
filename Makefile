
SHELL = /bin/bash

TEST_O_DIRECT := test_o_direct
TEST_SUBPAGE := test_subpage

DMGECKO := dm-gecko
GECKO := $(shell basename `pwd`)
DIST_FILE = $(GECKO).tar.gz
DMGECKO_MODNAME := $(DMGECKO)_mod

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)


ifeq ($(KERNELRELEASE),)
all:	user-space
all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
else
  obj-m += $(DMGECKO_MODNAME).o
  $(DMGECKO_MODNAME)-objs := $(DMGECKO).o dmg-kcopyd.o
endif

CC		:= gcc -O2 -Wall -g
LFLAGS	:= -lpthread


$(TEST_O_DIRECT): $(TEST_O_DIRECT).c
		$(CC) -o $@ $^ $(LFLAGS)

clean-$(TEST_O_DIRECT):
		rm -f $(TEST_O_DIRECT)

$(TEST_SUBPAGE): $(TEST_SUBPAGE).c
		$(CC) -o $@ $^ $(LFLAGS)

clean-$(TEST_SUBPAGE):
		rm -f $(TEST_SUBPAGE)


user-space: $(TEST_O_DIRECT) $(TEST_SUBPAGE)

clean-user-space: clean-$(TEST_O_DIRECT) clean-$(TEST_SUBPAGE)

dist: clean
	tar -cvzf /tmp/$(DIST_FILE) ../$(GECKO) --exclude=$(DIST_FILE) --exclude=".svn" --exclude=".git" --exclude=".hg" --exclude="TODO" && mv /tmp/$(DIST_FILE) . && scp $(DIST_FILE) fireless.cs.cornell.edu:public_html/gecko/

clean: clean-user-space clean-html
	rm -fr *.tgz *.tar.gz *.tmp *~ .tmp_versions *.o *.ko *.mod.c .*.cmd \
		Modules.symvers Module.symvers Module.markers modules.order

html: $(DMGECKO).c
	source-highlight -n $^ && scp $^.html \
	fireless.cs.cornell.edu:public_html/gecko/

clean-html:
	rm -f $(DMGECKO).c.html

ignore:
	svn propedit svn:ignore .

fireless: dist html
	 scp dm-gecko.c.html gecko.tar.gz fireless:public_html/gecko/

fresh: clean all
