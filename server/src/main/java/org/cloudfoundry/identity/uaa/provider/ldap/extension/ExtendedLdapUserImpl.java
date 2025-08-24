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
package org.cloudfoundry.identity.uaa.provider.ldap.extension;

import org.cloudfoundry.identity.uaa.authentication.NonStringPassword;
import org.cloudfoundry.identity.uaa.provider.ldap.ExtendedLdapUserDetails;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.ldap.userdetails.LdapUserDetails;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class ExtendedLdapUserImpl implements ExtendedLdapUserDetails {

    private String mailAttributeName = "mail";
    private String givenNameAttributeName;
    private String familyNameAttributeName;
    private String phoneNumberAttributeName;
    private String emailVerifiedAttributeName;
    private String dn;
    private transient NonStringPassword password = new NonStringPassword(null);
    private String username;
    private Collection<? extends GrantedAuthority> authorities = AuthorityUtils.NO_AUTHORITIES;
    private boolean accountNonExpired = true;
    private boolean accountNonLocked = true;
    private boolean credentialsNonExpired = true;
    private boolean enabled = true;
    private Map<String, String[]> attributes = new HashMap<>();

    public ExtendedLdapUserImpl(LdapUserDetails details) {
        setDn(details.getDn());
        setUsername(details.getUsername());
        setPassword(details.getPassword());
        setEnabled(details.isEnabled());
        setAccountNonExpired(details.isAccountNonExpired());
        setCredentialsNonExpired(details.isCredentialsNonExpired());
        setAccountNonLocked(details.isAccountNonLocked());
        setAuthorities(details.getAuthorities());
    }

    public ExtendedLdapUserImpl(LdapUserDetails details, Map<String, String[]> attributes) {
        this(details);
        this.attributes.putAll(attributes);
    }

    @Override
    public void eraseCredentials() {
        //noop
    }

    @Override
    public String[] getMail() {
        String[] mail = attributes.get(getMailAttributeName());
        if (mail == null) {
            mail = new String[0];
        }
        return mail;
    }

    @Override
    public Map<String, String[]> getAttributes() {
        return Collections.unmodifiableMap(attributes);
    }

    @Override
    public String[] getAttribute(String name, boolean caseSensitive) {
        if (name == null) {
            return null;
        }
        String[] value = getAttributes().get(name);
        if (value != null || caseSensitive) {
            return getAttributes().get(name);
        }
        for (Map.Entry<String, String[]> a : getAttributes().entrySet()) {
            if (a.getKey().equalsIgnoreCase(name)) {
                return a.getValue();
            }
        }
        return null;
    }

    public String getDn() {
        return dn;
    }

    public void setDn(String dn) {
        this.dn = dn;
    }

    public String getPassword() {
        return password.getPassword();
    }

    public void setPassword(String password) {
        this.password = new NonStringPassword(password);
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    public void setAuthorities(Collection<? extends GrantedAuthority> authorities) {
        this.authorities = authorities;
    }

    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }

    public void setAccountNonExpired(boolean accountNonExpired) {
        this.accountNonExpired = accountNonExpired;
    }

    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    public void setAccountNonLocked(boolean accountNonLocked) {
        this.accountNonLocked = accountNonLocked;
    }

    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }

    public void setCredentialsNonExpired(boolean credentialsNonExpired) {
        this.credentialsNonExpired = credentialsNonExpired;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getMailAttributeName() {
        return mailAttributeName;
    }

    public void setMailAttributeName(String mailAttributeName) {
        this.mailAttributeName = mailAttributeName;
    }

    public void setPhoneNumberAttributeName(String phoneNumberAttributeName) {
        this.phoneNumberAttributeName = phoneNumberAttributeName;
    }

    public void setGivenNameAttributeName(String givenNameAttributeName) {
        this.givenNameAttributeName = givenNameAttributeName;
    }

    public void setFamilyNameAttributeName(String familyNameAttributeName) {
        this.familyNameAttributeName = familyNameAttributeName;
    }

    @Override
    public String getEmailAddress() {
        String[] mailAddresses = getMail();
        return mailAddresses.length == 0 ? null : mailAddresses[0];
    }

    @Override
    public String getGivenName() {
        return getFirst(givenNameAttributeName, false);
    }

    @Override
    public String getFamilyName() {
        return getFirst(familyNameAttributeName, false);
    }

    @Override
    public String getPhoneNumber() {
        return getFirst(phoneNumberAttributeName, false);
    }

    @Override
    public String getExternalId() {
        return getDn();
    }

    public void setEmailVerifiedAttributeName(String emailVerifiedAttributeName) {
        this.emailVerifiedAttributeName = emailVerifiedAttributeName;
    }

    @Override
    public boolean isVerified() {
        return Boolean.valueOf(getFirst(emailVerifiedAttributeName, false));
    }

    protected String getFirst(String attributeName, boolean caseSensitive) {
        String[] result = getAttribute(attributeName, caseSensitive);
        if (result != null && result.length > 0) {
            return result[0];
        }
        return null;
    }
}
