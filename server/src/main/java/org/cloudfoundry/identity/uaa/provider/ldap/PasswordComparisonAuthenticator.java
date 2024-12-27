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

import lombok.Getter;
import lombok.Setter;
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
import java.util.function.Supplier;

/**
 * Unfortunately, the Spring PasswordComparisonAuthenticator is final, so we
 * can't extend it.
 * This password comparison authenticator lets you compare local bytes retrieved
 * by the initial user search.
 */
@Getter
@Setter
public class PasswordComparisonAuthenticator extends AbstractLdapAuthenticator {
    private static final Logger logger = LoggerFactory.getLogger(PasswordComparisonAuthenticator.class);
    private static final String BAD_CREDENTIALS = "Bad credentials";
    private static final String LDAP_COMPARE_OF_PASSWORD_ATTRIBUTE_FOR_USER_MESSAGE = "Performing LDAP compare of password attribute '{}' for user '{}'";

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
        Supplier<String> passProvider = () -> (String) authentication.getCredentials();

        SpringSecurityLdapTemplate ldapTemplate = new SpringSecurityLdapTemplate(getContextSource());

        for (String userDn : getUserDns(username)) {
            try {
                user = ldapTemplate.retrieveEntry(userDn, getUserAttributes());
            } catch (NameNotFoundException ignore) {
                // ignore
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
            logger.debug(LDAP_COMPARE_OF_PASSWORD_ATTRIBUTE_FOR_USER_MESSAGE, passwordAttributeName, user.getDn());
        }

        if (isLocalCompare()) {
            localCompareAuthenticate(user, passProvider.get());
        } else {
            String encodedPassword = passwordEncoder.encode(passProvider.get());
            byte[] passwordBytes = Utf8.encode(encodedPassword);
            searchAuthenticate(user, passwordBytes, ldapTemplate);
        }

        return user;
    }

    public DirContextOperations localCompareAuthenticate(DirContextOperations user, String password) {
        boolean match = false;
        try {
            Attributes attributes = user.getAttributes();
            Attribute attr = attributes.get(getPasswordAttributeName());
            if (attr.size() == 0) {
                throw new AuthenticationCredentialsNotFoundException("Missing " + getPasswordAttributeName() + " attribute.");
            }
            for (int i = 0; (attr != null) && (!match) && (i < attr.size()); i++) {
                Object valObject = attr.get(i);
                if (valObject != null && valObject instanceof byte[] valBytes) {
                    if (passwordEncoder instanceof DynamicPasswordComparator comparator) {
                        byte[] received = password.getBytes();
                        match = comparator.comparePasswords(received, valBytes);
                    } else {
                        String encodedPassword = passwordEncoder.encode(password);
                        byte[] passwordBytes = Utf8.encode(encodedPassword);
                        match = Arrays.equals(passwordBytes, valBytes);
                    }
                }
            }
        } catch (NamingException e) {
            throw new BadCredentialsException(BAD_CREDENTIALS, e);
        }
        if (!match) {
            throw new BadCredentialsException(BAD_CREDENTIALS);
        }
        return user;
    }

    public DirContextOperations searchAuthenticate(DirContextOperations user, byte[] passwordBytes,
                                                   SpringSecurityLdapTemplate ldapTemplate) {
        if (logger.isDebugEnabled()) {
            logger.debug(LDAP_COMPARE_OF_PASSWORD_ATTRIBUTE_FOR_USER_MESSAGE, passwordAttributeName, user.getDn());
        }

        if (!ldapTemplate.compare(user.getDn().toString(), passwordAttributeName, passwordBytes)) {
            throw new BadCredentialsException(messages.getMessage("PasswordComparisonAuthenticator.badCredentials", BAD_CREDENTIALS));
        }

        return user;
    }
}
