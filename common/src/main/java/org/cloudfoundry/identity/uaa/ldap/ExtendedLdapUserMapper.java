/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.ldap;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.ldap.extension.ExtendedLdapUserImpl;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.ldap.userdetails.LdapUserDetails;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.ldap.extension.SpringSecurityLdapTemplate.DN_KEY;

public class ExtendedLdapUserMapper extends LdapUserDetailsMapper {
    private static final Log logger = LogFactory.getLog(ExtendedLdapUserMapper.class);

    private String mailAttributeName="mail";
    @Override
    public UserDetails mapUserFromContext(DirContextOperations ctx, String username, Collection<? extends GrantedAuthority> authorities) {
        LdapUserDetails ldapUserDetails = (LdapUserDetails)super.mapUserFromContext(ctx, username, authorities);

        DirContextAdapter adapter = (DirContextAdapter) ctx;
        Map<String, String[]> record = new HashMap<String, String[]>();
        List<String> attributeNames = Collections.list(adapter.getAttributes().getIDs());
        for (String attributeName : attributeNames) {
            try {
                String[] values = adapter.getStringAttributes(attributeName);
                if (values == null || values.length == 0) {
                    logger.debug("No attribute value found for '" + attributeName + "'");
                } else {
                    record.put(attributeName, values);
                }
            } catch (ArrayStoreException x) {
                logger.debug("Attribute value is not a string for '" + attributeName + "'");
            }
        }
        record.put(DN_KEY, new String[] {adapter.getDn().toString()});
        ExtendedLdapUserImpl result = new ExtendedLdapUserImpl(ldapUserDetails, record);
        result.setMailAttributeName(getMailAttributeName());
        return result;
    }

    public String getMailAttributeName() {
        return mailAttributeName;
    }

    public void setMailAttributeName(String mailAttributeName) {
        this.mailAttributeName = mailAttributeName;
    }
}
