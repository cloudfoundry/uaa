/*
 * *****************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.provider.ldap;


import org.cloudfoundry.identity.uaa.provider.ldap.extension.ExtendedLdapUserImpl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

import static org.cloudfoundry.identity.uaa.provider.ldap.extension.SpringSecurityLdapTemplate.DN_KEY;

public class ExtendedLdapUserMapper extends LdapUserDetailsMapper {
    private static final Logger logger = LoggerFactory.getLogger(ExtendedLdapUserMapper.class);
    public static final String SUBSTITUTE_MAIL_ATTR_NAME = "substitute-mail-attribute";
    private String mailAttributeName = "mail";
    private String givenNameAttributeName;
    private String familyNameAttributeName;
    private String phoneNumberAttributeName;
    private String mailSubstitute;
    private boolean mailSubstituteOverrides;
    private String emailVerifiedAttributeName;

    @Override
    public UserDetails mapUserFromContext(DirContextOperations ctx, String username, Collection<? extends GrantedAuthority> authorities) {
        LdapUserDetails ldapUserDetails = (LdapUserDetails) super.mapUserFromContext(ctx, username, authorities);

        DirContextAdapter adapter = (DirContextAdapter) ctx;
        Map<String, String[]> record = new HashMap<>();
        List<String> attributeNames = Collections.list(adapter.getAttributes().getIDs());
        for (String attributeName : attributeNames) {
            try {
                Object[] objValues = adapter.getObjectAttributes(attributeName);
                String[] values = new String[objValues != null ? objValues.length : 0];
                for (int i = 0; i < values.length; i++) {
                    if (objValues != null && objValues[i] != null) {
                        if (objValues[i].getClass().isAssignableFrom(String.class)) {
                            values[i] = (String) objValues[i];
                        } else if (objValues[i] instanceof byte[] bytes) {
                            values[i] = new String(bytes);
                        } else {
                            values[i] = objValues[i].toString();
                        }
                    }
                }
                if (values == null || values.length == 0) {
                    logger.debug("No attribute value found for '{}'", attributeName);
                } else {
                    record.put(attributeName, values);
                }
            } catch (ArrayStoreException x) {
                logger.debug("Attribute value is not a string for '{}'", attributeName);
            }
        }
        record.put(DN_KEY, new String[]{adapter.getDn().toString()});
        String mailAttr = configureMailAttribute(username, record);
        ExtendedLdapUserImpl result = new ExtendedLdapUserImpl(ldapUserDetails, record);
        result.setMailAttributeName(mailAttr);
        result.setGivenNameAttributeName(givenNameAttributeName);
        result.setFamilyNameAttributeName(familyNameAttributeName);
        result.setPhoneNumberAttributeName(phoneNumberAttributeName);
        result.setEmailVerifiedAttributeName(emailVerifiedAttributeName);
        return result;
    }

    protected String configureMailAttribute(String username, Map<String, String[]> record) {
        //default behavior
        String result = getMailAttributeName();
        if (getMailSubstitute() != null) {
            String subemail = substituteMail(username);
            record.put(SUBSTITUTE_MAIL_ATTR_NAME, new String[]{subemail});
            if (isMailSubstituteOverridesLdap() ||
                    record.get(getMailAttributeName()) == null ||
                    record.get(getMailAttributeName()).length == 0) {
                result = SUBSTITUTE_MAIL_ATTR_NAME;
            }
        }
        return result;
    }

    protected String substituteMail(String username) {
        if (getMailSubstitute() == null) {
            return null;
        } else {
            return getMailSubstitute().replace("{0}", username);
        }
    }

    public String getMailAttributeName() {
        return mailAttributeName;
    }

    public void setMailAttributeName(String mailAttributeName) {
        this.mailAttributeName = mailAttributeName;
    }

    public String getPhoneNumberAttributeName() {
        return phoneNumberAttributeName;
    }

    public void setPhoneNumberAttributeName(String phoneNumberAttributeName) {
        this.phoneNumberAttributeName = phoneNumberAttributeName;
    }

    public String getGivenNameAttributeName() {
        return givenNameAttributeName;
    }

    public void setGivenNameAttributeName(String givenNameAttributeName) {
        this.givenNameAttributeName = givenNameAttributeName;
    }

    public String getFamilyNameAttributeName() {
        return familyNameAttributeName;
    }

    public void setFamilyNameAttributeName(String familyNameAttributeName) {
        this.familyNameAttributeName = familyNameAttributeName;
    }

    public String getMailSubstitute() {
        return mailSubstitute;
    }

    public void setMailSubstitute(String mailSubstitute) {
        if ("null".equals(mailSubstitute) || "".equals(mailSubstitute)) {
            mailSubstitute = null;
        }
        if (mailSubstitute != null && !mailSubstitute.contains("{0}")) {
            throw new IllegalArgumentException("Invalid mail substitute pattern, {0} is missing.");
        }
        this.mailSubstitute = mailSubstitute;
    }

    public boolean isMailSubstituteOverridesLdap() {
        return mailSubstituteOverrides;
    }

    public void setMailSubstituteOverridesLdap(boolean mailSubstituteOverridesLdap) {
        this.mailSubstituteOverrides = mailSubstituteOverridesLdap;
    }

    public String getEmailVerifiedAttributeName() {
        return emailVerifiedAttributeName;
    }

    public void setEmailVerifiedAttributeName(String emailVerifiedAttributeName) {
        this.emailVerifiedAttributeName = emailVerifiedAttributeName;
    }
}
