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
package org.cloudfoundry.identity.uaa.user;

import lombok.Getter;
import org.cloudfoundry.identity.uaa.authentication.NonStringPassword;
import org.springframework.security.core.GrantedAuthority;

import java.util.Date;
import java.util.List;

@Getter
public final class UaaUserPrototype {

    private String id = "NaN";

    private String username;

    private NonStringPassword password = new NonStringPassword(null);

    private String email;

    private String givenName;

    private String familyName;

    private String phoneNumber;

    private Date created;

    private Date modified;

    private String origin;

    private String externalId;

    private String salt;

    private Date passwordLastModified;

    private String zoneId;

    private List<? extends GrantedAuthority> authorities;

    private boolean verified;

    private boolean legacyVerificationBehavior;

    private boolean passwordChangeRequired;

    private Long lastLogonTime;

    private Long previousLogonTime;

    public UaaUserPrototype() {
    }

    public UaaUserPrototype(UaaUser user) {
        withVerified(user.isVerified())
                .withLegacyVerificationBehavior(user.isLegacyVerificationBehavior())
                .withEmail(user.getEmail())
                .withUsername(user.getUsername())
                .withPhoneNumber(user.getPhoneNumber())
                .withId(user.getId())
                .withOrigin(user.getOrigin())
                .withZoneId(user.getZoneId())
                .withAuthorities(user.getAuthorities())
                .withPassword(user.getPassword())
                .withFamilyName(user.getFamilyName())
                .withGivenName(user.getGivenName())
                .withExternalId(user.getExternalId())
                .withPasswordLastModified(user.getPasswordLastModified())
                .withLastLogonSuccess(user.getLastLogonTime())
                .withPreviousLogonSuccess(user.getPreviousLogonTime())
                .withSalt(user.getSalt())
                .withCreated(user.getCreated())
                .withModified(user.getModified())
                .withPasswordChangeRequired(user.isPasswordChangeRequired());
    }

    public UaaUserPrototype withId(String id) {
        this.id = id;
        return this;
    }

    public UaaUserPrototype withUsername(String username) {
        this.username = username;
        return this;
    }

    public String getPassword() {
        return password.getPassword();
    }

    NonStringPassword getNonStringPassword() {
        return password;
    }

    UaaUserPrototype withPassword(NonStringPassword password) {
        this.password = password;
        return this;
    }

    public UaaUserPrototype withPassword(String password) {
        this.password = new NonStringPassword(password);
        return this;
    }

    public UaaUserPrototype withEmail(String email) {
        this.email = email;
        return this;
    }

    public UaaUserPrototype withGivenName(String givenName) {
        this.givenName = givenName;
        return this;
    }

    public UaaUserPrototype withFamilyName(String familyName) {
        this.familyName = familyName;
        return this;
    }

    public UaaUserPrototype withPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
        return this;
    }

    public UaaUserPrototype withCreated(Date created) {
        this.created = created;
        return this;
    }

    public UaaUserPrototype withModified(Date modified) {
        this.modified = modified;
        return this;
    }

    public UaaUserPrototype withOrigin(String origin) {
        this.origin = origin;
        return this;
    }

    public UaaUserPrototype withExternalId(String externalId) {
        this.externalId = externalId;
        return this;
    }

    public UaaUserPrototype withSalt(String salt) {
        this.salt = salt;
        return this;
    }

    public UaaUserPrototype withPasswordLastModified(Date passwordLastModified) {
        this.passwordLastModified = passwordLastModified;
        return this;
    }

    public UaaUserPrototype withZoneId(String zoneId) {
        this.zoneId = zoneId;
        return this;
    }

    public UaaUserPrototype withAuthorities(List<? extends GrantedAuthority> authorities) {
        this.authorities = authorities;
        return this;
    }

    public UaaUserPrototype withVerified(boolean verified) {
        this.verified = verified;
        return this;
    }

    public UaaUserPrototype withLegacyVerificationBehavior(boolean legacyVerificationBehavior) {
        this.legacyVerificationBehavior = legacyVerificationBehavior;
        return this;
    }

    public UaaUserPrototype withPasswordChangeRequired(boolean requiresPasswordChange) {
        this.passwordChangeRequired = requiresPasswordChange;
        return this;
    }

    public UaaUserPrototype withLastLogonSuccess(Long lastLogonTime) {
        this.lastLogonTime = lastLogonTime;
        return this;
    }

    public UaaUserPrototype withPreviousLogonSuccess(Long previousLogonTime) {
        this.previousLogonTime = previousLogonTime;
        return this;
    }
}
