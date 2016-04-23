/*******************************************************************************
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
package org.cloudfoundry.identity.uaa.user;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

/**
 * User data for authentication against UAA's internal authentication provider.
 *
 * @author Luke Taylor
 * @author Dave Syer
 * @author Joel D'sa
 */
public class UaaUser {

    private final String id;

    private final String username;

    private final String password;

    private final String email;

    private final String givenName;

    private final String familyName;

    private final Date created;

    private final Date modified;

    private final String origin;

    private final String externalId;

    private final String salt;

    private final Date passwordLastModified;

    private final String phoneNumber;

    public String getZoneId() {
        return zoneId;
    }

    private final String zoneId;

    private final List<? extends GrantedAuthority> authorities;

    private boolean verified = false;

    private boolean legacyVerificationBehavior = false;

    public UaaUser(String username, String password, String email, String givenName, String familyName) {
        this("NaN", username, password, email, UaaAuthority.USER_AUTHORITIES, givenName, familyName, new Date(),
                new Date(), null, null, false, null, null, new Date());
    }

    public UaaUser(String username, String password, String email, String givenName, String familyName, String origin, String zoneId) {
        this("NaN", username, password, email, UaaAuthority.USER_AUTHORITIES, givenName, familyName, new Date(),
                new Date(), origin, null, false, zoneId, null, new Date());
    }

    public UaaUser(String id, String username, String password, String email,
                   List<? extends GrantedAuthority> authorities,
                   String givenName, String familyName, Date created, Date modified,
                   String origin, String externalId, boolean verified, String zoneId, String salt,
                   Date passwordLastModified) {
        this(new UaaUserPrototype()
                .withId(id)
                .withUsername(username)
                .withPassword(password)
                .withEmail(email)
                .withFamilyName(familyName)
                .withGivenName(givenName)
                .withCreated(created)
                .withModified(modified)
                .withAuthorities(authorities)
                .withOrigin(origin)
                .withExternalId(externalId)
                .withVerified(verified)
                .withZoneId(zoneId)
                .withSalt(salt)
                .withPasswordLastModified(passwordLastModified));
    }

    public UaaUser(UaaUserPrototype prototype) {
        Assert.hasText(prototype.getId(), "Id cannot be null");
        Assert.hasText(prototype.getUsername(), "Username cannot be empty");
        Assert.hasText(prototype.getEmail(), "Email is required");

        this.id = prototype.getId();
        this.username = prototype.getUsername();
        this.password = prototype.getPassword();
        this.email = prototype.getEmail();
        this.familyName = prototype.getFamilyName();
        this.givenName = prototype.getGivenName();
        this.created = prototype.getCreated();
        this.modified = prototype.getModified();
        this.authorities = prototype.getAuthorities();
        this.origin = prototype.getOrigin();
        this.externalId = prototype.getExternalId();
        this.verified = prototype.isVerified();
        this.zoneId = prototype.getZoneId();
        this.salt = prototype.getSalt();
        this.passwordLastModified = prototype.getPasswordLastModified();
        this.phoneNumber = prototype.getPhoneNumber();
        this.legacyVerificationBehavior = prototype.isLegacyVerificationBehavior();
    }

    public String getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getEmail() {
        return email;
    }

    public String getGivenName() {
        return givenName;
    }

    public String getFamilyName() {
        return familyName;
    }

    public String getOrigin() {
        return origin;
    }

    public String getExternalId() {
        return externalId;
    }

    public String getSalt() {
        return salt;
    }

    public List<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    public UaaUser id(String id) {
        if (!"NaN".equals(this.id)) {
            throw new IllegalStateException("Id already set");
        }
        return new UaaUser(id, username, password, email, authorities, givenName, familyName, created, modified, origin, externalId, verified, zoneId, salt, passwordLastModified);
    }

    public UaaUser authorities(Collection<? extends GrantedAuthority> authorities) {
        ArrayList<GrantedAuthority> values = new ArrayList<GrantedAuthority>(authorities);
        for (int i = 0; i < values.size(); i++) {
            GrantedAuthority authority = values.get(i);
            values.set(i, UaaAuthority.authority(authority.toString()));
        }
        if (!values.contains(UaaAuthority.UAA_USER)) {
            values.add(UaaAuthority.UAA_USER);
        }
        UaaUser user = new UaaUser(id, username, password, email, values, givenName, familyName, created, modified, origin, externalId, verified, zoneId, salt, passwordLastModified);
        return user;
    }

    @Override
    public String toString() {
        return "[UaaUser {id=" + id + ", username=" + username + ", email=" + email + ", givenName=" + givenName
                + ", familyName=" + familyName + "}]";
    }

    public Date getModified() {
        return modified;
    }

    public Date getCreated() {
        return created;
    }

    public Date getPasswordLastModified() {
        return passwordLastModified;
    }

    public UaaUser modifySource(String origin, String externalId) {
        return new UaaUser(
            new UaaUserPrototype()
                .withEmail(email)
                .withGivenName(givenName)
                .withFamilyName(familyName)
                .withPhoneNumber(phoneNumber)
                .withModified(modified)
                .withId(id)
                .withUsername(username)
                .withPassword(password)
                .withAuthorities(authorities)
                .withCreated(created)
                .withOrigin(origin)
                .withExternalId(externalId)
                .withVerified(verified)
                .withZoneId(zoneId)
                .withSalt(salt)
                .withPasswordLastModified(passwordLastModified));
    }

    public UaaUser modifyEmail(String email) {
        return new UaaUser(
            new UaaUserPrototype()
                .withEmail(email)
                .withGivenName(givenName)
                .withFamilyName(familyName)
                .withPhoneNumber(phoneNumber)
                .withModified(modified)
                .withId(id)
                .withUsername(username)
                .withPassword(password)
                .withAuthorities(authorities)
                .withCreated(created)
                .withOrigin(origin)
                .withExternalId(externalId)
                .withVerified(verified)
                .withZoneId(zoneId)
                .withSalt(salt)
                .withPasswordLastModified(passwordLastModified));
    }

    public UaaUser modifyOrigin(String origin) {
        return new UaaUser(
            new UaaUserPrototype()
                .withEmail(email)
                .withGivenName(givenName)
                .withFamilyName(familyName)
                .withPhoneNumber(phoneNumber)
                .withModified(modified)
                .withId(id)
                .withUsername(username)
                .withPassword(password)
                .withAuthorities(authorities)
                .withCreated(created)
                .withOrigin(origin)
                .withExternalId(externalId)
                .withVerified(verified)
                .withZoneId(zoneId)
                .withSalt(salt)
                .withPasswordLastModified(passwordLastModified));
    }

    public UaaUser modifyId(String id) {
        return new UaaUser(
            new UaaUserPrototype()
                .withEmail(email)
                .withGivenName(givenName)
                .withFamilyName(familyName)
                .withPhoneNumber(phoneNumber)
                .withModified(modified)
                .withId(id)
                .withUsername(username)
                .withPassword(password)
                .withAuthorities(authorities)
                .withCreated(created)
                .withOrigin(origin)
                .withExternalId(externalId)
                .withVerified(verified)
                .withZoneId(zoneId)
                .withSalt(salt)
                .withPasswordLastModified(passwordLastModified));
    }

    public UaaUser modifyUsername(String username) {
        return new UaaUser(
            new UaaUserPrototype()
                .withEmail(email)
                .withGivenName(givenName)
                .withFamilyName(familyName)
                .withPhoneNumber(phoneNumber)
                .withModified(modified)
                .withId(id)
                .withUsername(username)
                .withPassword(password)
                .withAuthorities(authorities)
                .withCreated(created)
                .withOrigin(origin)
                .withExternalId(externalId)
                .withVerified(verified)
                .withZoneId(zoneId)
                .withSalt(salt)
                .withPasswordLastModified(passwordLastModified));
    }

    public UaaUser modifyAttributes(String email, String givenName, String familyName, String phoneNumber) {
        return new UaaUser(new UaaUserPrototype()
                .withEmail(email)
                .withGivenName(givenName)
                .withFamilyName(familyName)
                .withPhoneNumber(phoneNumber)
                .withModified(modified)
                .withId(id)
                .withUsername(username)
                .withPassword(password)
                .withAuthorities(authorities)
                .withCreated(created)
                .withOrigin(origin)
                .withExternalId(externalId)
                .withVerified(verified)
                .withZoneId(zoneId)
                .withSalt(salt)
                .withPasswordLastModified(passwordLastModified));
    }

    public boolean isVerified() {
        return verified;
    }

    public void setVerified(boolean verified) {
        this.verified = verified;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public boolean isLegacyVerificationBehavior() {
        return legacyVerificationBehavior;
    }
}
