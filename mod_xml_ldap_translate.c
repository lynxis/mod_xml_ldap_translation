/*
 * FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 * Copyright (C) 2005-2010, Anthony Minessale II <anthm@freeswitch.org>
 *
 * Version: MPL 1.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 *
 * The Initial Developer of the Original Code is
 * Anthony Minessale II <anthm@freeswitch.org>
 * Portions created by the Initial Developer are Copyright (C)
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Anthony Minessale II <anthm@freeswitch.org>
 * Bret McDanel <trixter AT 0xdecafbad.com>
 * Justin Cassidy <xachenant@hotmail.com>
 * John Skopis <john+fs@skopis.com>
 * 
 * mod_xml_ldap_translate.c -- LDAP XML Gateway
 *
 */
#include <switch.h>
#include <stdlib.h>
#include <string.h>
#ifdef MSLDAP
#include <windows.h>
#include <winldap.h>
#include <winber.h>
#define LDAP_OPT_SUCCESS LDAP_SUCCESS
#else
#include <lber.h>
#include <ldap.h>
#include <sasl/sasl.h>
#include "lutil_ldap.h"
#endif

typedef enum {
	XML_LDAP_CONFIG = 0,
	XML_LDAP_DIRECTORY,
	XML_LDAP_DIALPLAN,
	XML_LDAP_PHRASE
} xml_ldap_translate_query_type_t;

SWITCH_MODULE_LOAD_FUNCTION(mod_xml_ldap_translate_load);
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_xml_ldap_translate_shutdown);
SWITCH_MODULE_DEFINITION(mod_xml_ldap_translate, mod_xml_ldap_translate_load, mod_xml_ldap_translate_shutdown, NULL);

struct trans;
typedef struct trans {
	char *ldapname;
	char *xmlname;
    char *attrname;
	struct trans *next;
} trans_t;

struct trans_group;
typedef struct trans_group {
	char *name;
	struct trans *trans;
	struct trans_group *child;
	struct trans_group *next;
} trans_group_t;

typedef struct xml_binding {
	char *bindings;
	char *host;
	char *basedn;
	char *binddn;
	char *bindpass;
	char *filter;
	char **attrs;
	trans_t *trans;	
	trans_group_t *trans_group;
	lutilSASLdefaults *defaults;
} xml_binding_t;

typedef struct ldap_c {
	LDAP *ld;
	LDAPMessage *msg;
	LDAPMessage *entry;
	BerElement *berkey;
	BerValue **berval;
	char *key;
	char *val;
	char **keyvals;
	char **valvals;
	char *sp;
} ldap_ctx;

static switch_status_t xml_ldap_translate_directory_result(void *ldap_connection, xml_binding_t *binding, switch_xml_t *xml, int *off);
static switch_status_t xml_ldap_translate_dialplan_result(void *ldap_connection, xml_binding_t *binding, switch_xml_t *xml, int *off);
static int xml_ldap_translate_set_trans(trans_t **first, switch_xml_t *parent_tag);
static int xml_ldap_translate_set_group(trans_group_t **group, switch_xml_t *parent_tag);

static void xml_ldap_translate_result_trans(void *ldap_connection, trans_t *trans, switch_xml_t *parent_tag, int *off);
static void xml_ldap_translate_result_group(void *ldap_connection, trans_group_t *group, switch_xml_t *parent_tag, int *off);

#define XML_LDAP_TRANSLATE_SYNTAX "[debug_on|debug_off]"

SWITCH_STANDARD_API(xml_ldap_translate_function)
{
	if (session) {
		return SWITCH_STATUS_FALSE;
	}

	if (zstr(cmd)) {
		goto usage;
	}

	if (!strcasecmp(cmd, "debug_on")) {
	} else if (!strcasecmp(cmd, "debug_off")) {
	} else {
		goto usage;
	}

	stream->write_function(stream, "OK\n");
	return SWITCH_STATUS_SUCCESS;

  usage:
	stream->write_function(stream, "USAGE: %s\n", XML_LDAP_TRANSLATE_SYNTAX);
	return SWITCH_STATUS_SUCCESS;
}
/* you must free the pointer you got returned from it 
static char * xml_ldap_trans_xmlname(xml_binding_t *binding, char *ldapname)
{
	for ( trans_t *iter = binding->trans; iter ; iter = iter->next ) {
		if(!strcmp(ldapname, iter->ldapname))
			return strdup(iter->xmlname);
	}
	return NULL;
}
*/
static switch_status_t xml_ldap_translate_result(void *ldap_connection, xml_binding_t *binding, switch_xml_t *xml, int *off,
									   const xml_ldap_translate_query_type_t query_type)
{
	switch (query_type) {
	case XML_LDAP_DIRECTORY:
		return xml_ldap_translate_directory_result(ldap_connection, binding, xml, off);

	case XML_LDAP_DIALPLAN:
		return xml_ldap_translate_dialplan_result(ldap_connection, binding, xml, off);

	default:
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "xml_ldap_translate_result \n");		
		return SWITCH_STATUS_FALSE;
	}
}

static switch_status_t xml_ldap_translate_dialplan_result(void *ldap_connection, xml_binding_t *binding, switch_xml_t *xml, int *off)
{
	return SWITCH_STATUS_FALSE;
}

static void xml_ldap_translate_result_group(void  *ldap_connection, trans_group_t *group, switch_xml_t *parent_tag, int *off) {
	switch_xml_t group_tag = NULL;

    if(!group)
        return;
    for (; group ; group = group->next) {
        group_tag = switch_xml_add_child_d(*parent_tag, group->name, (*off)++);
        if(group->trans)
            xml_ldap_translate_result_trans(ldap_connection, group->trans, &group_tag, off);
        if(group->child)
            xml_ldap_translate_result_group(ldap_connection, group->child, &group_tag, off);
    }
}
static void xml_ldap_translate_result_trans(void *ldap_connection, trans_t *trans, switch_xml_t *parent_tag, int *off) {
	struct ldap_c *ldap = ldap_connection;
    switch_xml_t attr_tag;
	trans_t *iter;
	for (iter = trans ; iter ; iter = iter->next) {
		/* search for the field with the same name as ldapname */
		for (ldap->entry = ldap_first_entry(ldap->ld, ldap->msg); ldap->entry != NULL; ldap->entry = ldap_next_entry(ldap->ld, ldap->entry)) {
			for(ldap->key = ldap_first_attribute(ldap->ld, ldap->entry, &ldap->berkey); ldap->key; ldap->key = ldap_next_attribute(ldap->ld, ldap->entry, ldap->berkey)) {		
				/* key is not our searched key */
				if(strcmp(ldap->key, iter->ldapname))
					continue;
				ldap->berval = ldap_get_values_len(ldap->ld, ldap->entry, ldap->key);
				if(ldap->berval == NULL) {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "no values found for key %s", ldap->key);
					continue;
				}
				if((*ldap->berval)->bv_len == 0 ) {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "value is empty for key %s", ldap->key);
					continue;
				}
				if((*ldap->berval)->bv_val == NULL ) {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "value is NULL for key %s", ldap->key);
					continue;
				}

				/* we use only the first argument/val pair. maybe someone write support for it */	
				ldap->val = (*ldap->berval)->bv_val;
				attr_tag = switch_xml_add_child_d(*parent_tag, iter->attrname, (*off)++);
				switch_xml_set_attr_d(attr_tag, "name", iter->xmlname);
				switch_xml_set_attr_d(attr_tag, "value", ldap->val);

				
				if (ldap->key) {
					ldap_memfree(ldap->key);
				}

				if (ldap->berval) {
					ldap_value_free_len(ldap->berval);
				}
			}
		}
	}
}

static switch_status_t xml_ldap_translate_directory_result(void *ldap_connection, xml_binding_t *binding, switch_xml_t *parent_tag, int *off)
{
	struct ldap_c *ldap = ldap_connection;
/* iter thought the groups and search for the trans. every group will become a tag and every trans without a value wont write out to the xml */	

	if(binding->trans_group)
	  	xml_ldap_translate_result_group(ldap_connection, binding->trans_group, parent_tag, off);

	if (ldap->berkey) {
		ber_free(ldap->berkey, 0);
	}
	return SWITCH_STATUS_SUCCESS;
}


static switch_xml_t xml_ldap_translate_search(const char *section, const char *tag_name, const char *key_name, const char *key_value, switch_event_t *params,
									void *user_data)
{
	xml_binding_t *binding = (xml_binding_t *) user_data;
	switch_event_header_t *hi;

	switch_xml_t xml = NULL, sub = NULL;

	struct ldap_c ldap_connection;
	struct ldap_c *ldap = &ldap_connection;

	int auth_method = LDAP_AUTH_SIMPLE;
	int desired_version = LDAP_VERSION3;
	xml_ldap_translate_query_type_t query_type;
	char *dir_exten = NULL, *dir_domain = NULL;

	char *search_filter = NULL, *search_base = NULL;
	int off = 0, ret = 1;

	char *buf;
	buf = malloc(4096);


	if (!binding) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "No bindings...sorry bud returning now\n");
		return NULL;
	}

	if (!strcmp(section, "configuration")) {
		query_type = XML_LDAP_CONFIG;
	} else if (!strcmp(section, "directory")) {
		query_type = XML_LDAP_DIRECTORY;
	} else if (!strcmp(section, "dialplan")) {
		query_type = XML_LDAP_DIALPLAN;
	} else if (!strcmp(section, "phrases")) {
		query_type = XML_LDAP_PHRASE;
	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Invalid section\n");
		return NULL;
	}

	if (params) {
		if ((hi = params->headers)) {
			for (; hi; hi = hi->next) {
				switch (query_type) {
				case XML_LDAP_CONFIG:
					break;

				case XML_LDAP_DIRECTORY:
					if (!strcmp(hi->name, "user")) {
						dir_exten = strdup(hi->value);
					} else if (!strcmp(hi->name, "domain")) {
						dir_domain = strdup(hi->value);
					}
					break;

				case XML_LDAP_DIALPLAN:
				case XML_LDAP_PHRASE:
					break;
				}
			}
			switch (query_type) {
			case XML_LDAP_CONFIG:
				break;

			case XML_LDAP_DIRECTORY:
				if (dir_exten && dir_domain) {
					if ((xml = switch_xml_new("directory"))) {
						switch_xml_set_attr_d(xml, "type", "freeswitch/xml");

						if ((sub = switch_xml_add_child_d(xml, "section", off++))) {
							switch_xml_set_attr_d(sub, "name", "directory");
						}

						if ((sub = switch_xml_add_child_d(sub, "domain", off++))) {
							switch_xml_set_attr_d(sub, "name", dir_domain);
						}

						if ((sub = switch_xml_add_child_d(sub, "user", off++))) {
							switch_xml_set_attr_d(sub, "id", dir_exten);
						}

					}

					search_filter = switch_mprintf(binding->filter, dir_exten);
					search_base = switch_mprintf(binding->basedn, dir_domain);

					free(dir_exten);
					dir_exten = NULL;

					free(dir_domain);
					dir_domain = NULL;

				} else {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG,
									  "Something bad happened during the query construction phase likely exten(%s) or domain(%s) is null\n", dir_exten,
									  dir_domain);
					goto cleanup;
				}
				break;

			case XML_LDAP_DIALPLAN:
				if ((xml = switch_xml_new("document"))) {
					switch_xml_set_attr_d(xml, "type", "freeswitch/xml");

					if ((sub = switch_xml_add_child_d(xml, "section", off++))) {
						switch_xml_set_attr_d(sub, "name", "dialplan");
					}

					sub = switch_xml_add_child_d(xml, "context", off++);
				}

				break;

			case XML_LDAP_PHRASE:
				break;
			}
		} else {
			goto cleanup;
		}
	}



	if ((ldap->ld = (LDAP *) ldap_init(binding->host, LDAP_PORT)) == NULL) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Unable to connect to ldap server.%s\n", binding->host);
		goto cleanup;
	}

	if (ldap_set_option(ldap->ld, LDAP_OPT_PROTOCOL_VERSION, &desired_version) != LDAP_OPT_SUCCESS) {
		goto cleanup;
	}

	ldap_set_option(ldap->ld, LDAP_OPT_X_SASL_SECPROPS, &ldap->sp);



	if (binding->binddn) {
		if (ldap_bind_s(ldap->ld, binding->binddn, binding->bindpass, auth_method) != LDAP_SUCCESS) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Unable to bind to ldap server %s as %s\n", binding->host, binding->binddn);
			goto cleanup;
		}
	} else {
		if (ldap_sasl_interactive_bind_s
			(ldap->ld, NULL, binding->defaults->mech, NULL, NULL, (unsigned) (intptr_t) LDAP_SASL_SIMPLE, lutil_sasl_interact,
			 binding->defaults) != LDAP_SUCCESS) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Unable to sasl_bind to ldap server %s as %s\n", binding->host,
							  binding->defaults->authcid);
			goto cleanup;
		}
	}
	
	if (ldap_search_s(ldap->ld, search_base, LDAP_SCOPE_SUBTREE, search_filter, NULL, 0, &ldap->msg) != LDAP_SUCCESS) {
		goto cleanup;
	}

	if (ldap_count_entries(ldap->ld, ldap->msg) <= 0) {
        ret = 1;
		goto cleanup;
	}

	if (sub && xml_ldap_translate_result(&ldap_connection, binding, &sub, &off, query_type) != SWITCH_STATUS_SUCCESS) {
        ret = 1;
		goto cleanup;
	}

	ret = 0;

  cleanup:
	if (ldap->msg) {
		ldap_msgfree(ldap->msg);
	}

	if (ldap->ld) {
		ldap_unbind_s(ldap->ld);
	}

	switch_safe_free(search_filter);
	switch_safe_free(search_base);

	if (ret) {
		switch_xml_free(xml);
		return NULL;
	}

	return xml;
}


static switch_status_t do_config(void)
{
	char *cf = "xml_ldap_translate.conf";
	switch_xml_t cfg, xml, bindings_tag, binding_tag, param, trans_tag;
	xml_binding_t *binding = NULL;
	int x = 0;

	if (!(xml = switch_xml_open_cfg(cf, &cfg, NULL))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Open of %s failed\n", cf);
		return SWITCH_STATUS_TERM;
	}

	if (!(bindings_tag = switch_xml_child(cfg, "bindings"))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Missing <bindings> tag!\n");
		goto done;
	}

	for (binding_tag = switch_xml_child(bindings_tag, "binding"); binding_tag; binding_tag = binding_tag->next) {
		char *bname = (char *) switch_xml_attr_soft(binding_tag, "name");

		if (!(binding = malloc(sizeof(*binding)))) {
			goto done;
		}
		memset(binding, 0, sizeof(xml_binding_t));

		if (!(binding->defaults = malloc(sizeof(lutilSASLdefaults)))) {
			goto done;
		}
		memset(binding->defaults, 0, sizeof(lutilSASLdefaults));

		for (param = switch_xml_child(binding_tag, "param"); param; param = param->next) {

			char *var = (char *) switch_xml_attr_soft(param, "name");
			char *val = (char *) switch_xml_attr_soft(param, "value");

			if (!strcasecmp(var, "filter")) {
				binding->bindings = (char *) switch_xml_attr_soft(param, "bindings");
				if (val) {
					binding->filter = strdup(val);
				}
			} else if (!strcasecmp(var, "basedn")) {
				binding->basedn = strdup(val);
			} else if (!strcasecmp(var, "binddn")) {
				binding->binddn = strdup(val);
			} else if (!strcasecmp(var, "bindpass")) {
				binding->bindpass = strdup(val);
			} else if (!strcasecmp(var, "host")) {
				binding->host = strdup(val);
			} else if (!strcasecmp(var, "mech")) {
				binding->defaults->mech = strdup(val);
			} else if (!strcasecmp(var, "realm")) {
				binding->defaults->realm = strdup(val);
			} else if (!strcasecmp(var, "authcid")) {
				binding->defaults->authcid = strdup(val);
			} else if (!strcasecmp(var, "authzid")) {
				binding->defaults->authzid = strdup(val);
			}
		}
		if (!binding->basedn || !binding->filter) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "You must define \"basedn\", and \"filter\" in mod_xml_translate_ldap_translate.conf.xml\n");
			/* TODO will this create a memory leak ? */
			continue;
		}
		
		if (!(trans_tag = switch_xml_child(binding_tag, "trans")))  {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "You must define trans tag in mod_xml_ldap_translate.conf.xml\n");
			/* TODO memory leak ? */
			continue;
		}
		xml_ldap_translate_set_group(&(binding->trans_group), &trans_tag);
		xml_ldap_translate_set_trans(&(binding->trans), &trans_tag);
		/* TODO check for a group, if no group configured... */
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "Binding [%s] XML Fetch Function [%s] (%s) [%s]\n",
						  zstr(bname) ? "N/A" : bname, binding->basedn, binding->filter, binding->bindings ? binding->bindings : "all");

		switch_xml_bind_search_function(xml_ldap_translate_search, switch_xml_parse_section_string(bname), binding);

		x++;
		binding = NULL;
		
	}

  done:
	switch_xml_free(xml);

	return SWITCH_STATUS_SUCCESS;
}
/* 
 * parent targetting the layer above the tran tags
  */
static int xml_ldap_translate_set_trans(trans_t **first, switch_xml_t *parent_tag) {
	trans_t *iter, *prev;
	switch_xml_t tran;
	prev = NULL;
	iter = *first;
	for (tran = switch_xml_child(*parent_tag, "tran"); tran; tran = tran->next) {
		char *xmlname = (char *) switch_xml_attr_soft(tran, "xmlname");
		char *attrname = (char *) switch_xml_attr_soft(tran, "attrname");
		char *ldapname = (char *) switch_xml_attr_soft(tran, "ldapname");
		if((!xmlname) || (!ldapname) || (!attrname)) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "attrname %s, xmlname %s or ldapname %s is empty or null\n", attrname, xmlname, ldapname );
			continue;
		}
		iter = calloc(1, sizeof(struct trans));
		if(prev)
			prev->next = iter;
        else
            *first = iter;
		iter->next = NULL;
		iter->xmlname = strdup(xmlname);
		iter->ldapname = strdup(ldapname);
        iter->attrname = strdup(attrname);
        prev = iter;
	}
	return 0;
}
/* 
 */
static int xml_ldap_translate_set_group(trans_group_t **group, switch_xml_t *parent_tag) {
	switch_xml_t group_tag = NULL;
	trans_group_t *iter, *prev;

	prev = NULL;
    if(!group) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "grouppointer is NULL !\n");
		return 1;
	}
	for (group_tag = switch_xml_child(*parent_tag, "group"); group_tag; group_tag = group_tag->next) {
		char *groupname = (char *) switch_xml_attr_soft(group_tag, "name");
		if(!groupname) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "groupname not defined or empty !\n");
			continue;
		}
		iter = calloc(1, sizeof(trans_group_t));
		if(prev)
			prev->next = iter;
        else
            *group = iter;
        iter->next = NULL;
		iter->name = strdup(groupname);
		prev = iter;
		xml_ldap_translate_set_group(&(iter->child), &group_tag);
		xml_ldap_translate_set_trans(&(iter->trans), &group_tag);
	}
	return 0;
}

SWITCH_MODULE_LOAD_FUNCTION(mod_xml_ldap_translate_load)
{
	switch_api_interface_t *xml_ldap_translate_api_interface;

	/* connect my internal structure to the blank pointer passed to me */
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);

	SWITCH_ADD_API(xml_ldap_translate_api_interface, "xml_ldap_translate", "XML LDAP", xml_ldap_translate_function, XML_LDAP_SYNTAX);
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "XML LDAP module loading...\n");

	if (do_config() != SWITCH_STATUS_SUCCESS) {
		return SWITCH_STATUS_FALSE;
	}

	/* indicate that the module should continue to be loaded */
	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_xml_ldap_translate_shutdown)
{
	/* free pointer ? */
	return SWITCH_STATUS_SUCCESS;
}

/* For Emacs:
 * Local Variables:
 * mode:c
 * indent-tabs-mode:t
 * tab-width:4
 * c-basic-offset:4
 * End:
 * For VIM:
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4:
 */
