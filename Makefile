BASE=../../../..

LDAP_BUILDDIR=/usr/lib/x86_64-linux-gnu
LDAPLA=$(LDAP_BUILDDIR)/libldap_r.la
LIBLBERLA=$(LDAP_BUILDDIR)/libraries/liblber/liblber.la
LIBLUTILA=$(LDAP_BUILDDIR)/libraries/liblutil/liblutil.a

LOCAL_CFLAGS=-DWITH_OPENLDAP -DLDAP_DEPRECATED -I$(LDAP_DIR)/include -lldap

#LOCAL_LIBADD=$(LDAPLA) $(LIBLBERLA) $(LIBLUTILA)

include $(BASE)/build/modmake.rules


