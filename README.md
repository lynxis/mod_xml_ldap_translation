# mod_xml_ldap_translation
This module can translate several fields and params from a ldap into your dialplan or directory.

# Requirements to compile
You will need *libldap* with development files.

# Example Config
Add to *autoload_configs/modules.conf.xml*

    <load module="mod_xml_ldap_translation"/>
    
Copy example *xml_ldap_translate.conf.xml* into your autoload_configs/ directory.

# How to compile

    # go into your freeswitch source directory.
    cd freeswitch/src/mod/xml_int/
    git clone git://github.com/lynxis/mod_xml_ldap_translation.git mod_xml_ldap_translation
    # be carefull of renaming it, because freeswitch is checking every directory for files named '.c' and '.cpp'
    # to validate a module exists. Just don't rename the directory name within xml_int.
    cd ../../../
    # now within freeswitch/
    echo 'xml_int/mod_xml_ldap_translation' >> freeswitch/modules.conf
    make
