BASE=../../../..

LOCAL_CFLAGS=-DWITH_OPENLDAP -DLDAP_DEPRECATED -I$(LDAP_DIR)/include -lldap

include $(BASE)/build/modmake.rules


