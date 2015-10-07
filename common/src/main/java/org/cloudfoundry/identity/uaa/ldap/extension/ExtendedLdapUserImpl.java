/*
 * ******************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
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
package org.cloudfoundry.identity.uaa.ldap.extension;

import org.cloudfoundry.identity.uaa.ldap.ExtendedLdapUserDetails;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.ldap.userdetails.LdapUserDetails;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class ExtendedLdapUserImpl implements ExtendedLdapUserDetails {

    private String mailAttributeName = "mail";
    private String givenNameAttributeName = "given_name";
    private String familyNameAttributeName = "family_name";
    private String phoneNumberAttributeName = "phone";
    private String dn;
    private String password;
    private String username;
    private Collection<? extends GrantedAuthority> authorities = AuthorityUtils.NO_AUTHORITIES;
    private boolean accountNonExpired = true;
    private boolean accountNonLocked = true;
    private boolean credentialsNonExpired = true;
    private boolean enabled = true;
    // PPolicy data
    private int timeBeforeExpiration = Integer.MAX_VALUE;
    private int graceLoginsRemaining = Integer.MAX_VALUE;
    private Map<String,String[]> attributes = new HashMap<>();

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
    public ExtendedLdapUserImpl(LdapUserDetails details, Map<String,String[]> attributes) {
        this(details);
        this.attributes.putAll(attributes);
    }

    @Override
    public String[] getMail() {
        String[] mail = attributes.get(getMailAttributeName());
        if (mail==null) {
            mail = new String[0];
        }
        return mail;
    }

    @Override
    public Map<String, String[]> getAttributes() {
        return Collections.unmodifiableMap(attributes);
    }

    public String getDn() {
        return dn;
    }

    public void setDn(String dn) {
        this.dn = dn;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
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

    public int getTimeBeforeExpiration() {
        return timeBeforeExpiration;
    }

    public void setTimeBeforeExpiration(int timeBeforeExpiration) {
        this.timeBeforeExpiration = timeBeforeExpiration;
    }

    public int getGraceLoginsRemaining() {
        return graceLoginsRemaining;
    }

    public void setGraceLoginsRemaining(int graceLoginsRemaining) {
        this.graceLoginsRemaining = graceLoginsRemaining;
    }

    public String getMailAttributeName() {
        return mailAttributeName;
    }

    public void setMailAttributeName(String mailAttributeName) {
        this.mailAttributeName = mailAttributeName.toLowerCase();
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

    @Override
    public String getEmailAddress() {
        String[] mailAddresses = getMail();
        return mailAddresses.length == 0 ? null : mailAddresses[0];
    }

    @Override
    public String getGivenName() {
        String[] attrValues = this.attributes.get(givenNameAttributeName);
        if(attrValues == null) return null;
        return attrValues[0];
    }

    @Override
    public String getFamilyName() {
        String[] attrValues = this.attributes.get(familyNameAttributeName);
        if(attrValues == null) return null;
        return attrValues[0];
    }

    @Override
    public String getPhoneNumber() {
        String[] attrValues = this.attributes.get(phoneNumberAttributeName);
        if(attrValues == null) return null;
        return attrValues[0];
    }

    @Override
    public String getExternalId() {
        return getDn();
    }
}
