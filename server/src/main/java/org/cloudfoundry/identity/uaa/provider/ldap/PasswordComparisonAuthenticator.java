/*
 * ******************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * ******************************************************************************
 */
package org.cloudfoundry.identity.uaa.provider.ldap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ldap.NameNotFoundException;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.codec.Utf8;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.ldap.SpringSecurityLdapTemplate;
import org.springframework.security.ldap.authentication.AbstractLdapAuthenticator;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import java.util.Arrays;

/**
 * Unfortunately the Spring PasswordComparisonAuthenticator is final, so we
 * can't extend it.
 * This password comparison authenticator lets you compare local bytes retrieved
 * by the initial user search.
 */

public class PasswordComparisonAuthenticator extends AbstractLdapAuthenticator {
    private static final Logger logger = LoggerFactory.getLogger(PasswordComparisonAuthenticator.class);

    private boolean localCompare;
    private String passwordAttributeName;
    private PasswordEncoder passwordEncoder = new LdapShaPasswordEncoder();

    public PasswordComparisonAuthenticator(BaseLdapPathContextSource contextSource) {
        super(contextSource);
    }

    @Override
    public DirContextOperations authenticate(Authentication authentication) {
        DirContextOperations user = null;
        String username = authentication.getName();
        String password = (String) authentication.getCredentials();

        SpringSecurityLdapTemplate ldapTemplate = new SpringSecurityLdapTemplate(getContextSource());

        for (String userDn : getUserDns(username)) {
            try {
                user = ldapTemplate.retrieveEntry(userDn, getUserAttributes());
            } catch (NameNotFoundException ignore) {
            }
            if (user != null) {
                break;
            }
        }

        if (user == null && getUserSearch() != null) {
            user = getUserSearch().searchForUser(username);
        }

        if (user == null) {
            throw new UsernameNotFoundException("User not found: " + username);
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Performing LDAP compare of password attribute '" + passwordAttributeName + "' for user '" +
                            user.getDn() + "'");
        }

        if (isLocalCompare()) {
            localCompareAuthenticate(user, password);
        } else {
            String encodedPassword = passwordEncoder.encode(password);
            byte[] passwordBytes = Utf8.encode(encodedPassword);
            searchAuthenticate(user, passwordBytes, ldapTemplate);
        }

        return user;

    }

    public void localCompareAuthenticate(DirContextOperations user, String password) {
        boolean match = false;
        try {
            Attributes attributes = user.getAttributes();
            Attribute attr = attributes.get(getPasswordAttributeName());
            if (attr == null || attr.size() == 0) {
                throw new AuthenticationCredentialsNotFoundException("Missing "+getPasswordAttributeName()+" attribute.");
            }
            for (int i = 0; (!match) && (i < attr.size()); i++) {
                Object valObject = attr.get(i);
                if (valObject instanceof byte[]) {
                    if (passwordEncoder instanceof DynamicPasswordComparator) {
                        byte[] received = password.getBytes();
                        byte[] stored = (byte[]) valObject;
                        match = ((DynamicPasswordComparator) passwordEncoder).comparePasswords(received, stored);
                    } else {
                        String encodedPassword = passwordEncoder.encode(password);
                        byte[] passwordBytes = Utf8.encode(encodedPassword);
                        match = Arrays.equals(passwordBytes, (byte[]) valObject);
                    }
                }
            }
        } catch (NamingException e) {
            throw new BadCredentialsException("Bad credentials", e);
        }
        if (!match)
            throw new BadCredentialsException("Bad credentials");
    }

    public DirContextOperations searchAuthenticate(DirContextOperations user, byte[] passwordBytes,
                    SpringSecurityLdapTemplate ldapTemplate) {
        if (logger.isDebugEnabled()) {
            logger.debug("Performing LDAP compare of password attribute '" + passwordAttributeName + "' for user '" +
                            user.getDn() + "'");
        }

        if (!ldapTemplate.compare(user.getDn().toString(), passwordAttributeName, passwordBytes)) {
            throw new BadCredentialsException(messages.getMessage("PasswordComparisonAuthenticator.badCredentials",
                            "Bad credentials"));
        }

        return user;
    }

    public void setPasswordAttributeName(String passwordAttribute) {
        this.passwordAttributeName = passwordAttribute;
    }

    public String getPasswordAttributeName() {
        return passwordAttributeName;
    }

    public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    public PasswordEncoder getPasswordEncoder() {
        return passwordEncoder;
    }

    public boolean isLocalCompare() {
        return localCompare;
    }

    public void setLocalCompare(boolean localCompare) {
        this.localCompare = localCompare;
    }

}
