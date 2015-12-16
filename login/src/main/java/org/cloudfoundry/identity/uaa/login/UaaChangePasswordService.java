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
package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.password.event.PasswordChangeEvent;
import org.cloudfoundry.identity.uaa.password.event.PasswordChangeFailureEvent;
import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.scim.validate.PasswordValidator;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Date;
import java.util.List;

import static org.springframework.http.HttpStatus.UNPROCESSABLE_ENTITY;

public class UaaChangePasswordService implements ChangePasswordService, ApplicationEventPublisherAware {

    private final ScimUserProvisioning scimUserProvisioning;
    private final PasswordValidator passwordValidator;
    private ApplicationEventPublisher publisher;

    public UaaChangePasswordService(ScimUserProvisioning scimUserProvisioning, PasswordValidator passwordValidator) {
        this.scimUserProvisioning = scimUserProvisioning;
        this.passwordValidator = passwordValidator;
    }

    @Override
    public void changePassword(String username, String currentPassword, String newPassword) {
        if (username == null || currentPassword == null) {
            throw new BadCredentialsException(username);
        }
        passwordValidator.validate(newPassword);
        List<ScimUser> results = scimUserProvisioning.query("userName eq \"" + username + "\"");
        if (results.isEmpty()) {
            throw new ScimResourceNotFoundException("User not found");
        }
        ScimUser user = results.get(0);
        UaaUser uaaUser = getUaaUser(user);
        try {
            if (scimUserProvisioning.checkPasswordMatches(user.getId(), newPassword)) {
                throw new InvalidPasswordException("Your new password cannot be the same as the old password.", UNPROCESSABLE_ENTITY);
            }
            scimUserProvisioning.changePassword(user.getId(), currentPassword, newPassword);
            publish(new PasswordChangeEvent("Password changed", uaaUser, SecurityContextHolder.getContext().getAuthentication()));
        } catch (Exception e) {
            publish(new PasswordChangeFailureEvent(e.getMessage(), uaaUser, SecurityContextHolder.getContext().getAuthentication()));
            throw e;
        }
    }

    private UaaUser getUaaUser(ScimUser scimUser) {
        Date today = new Date();
        return new UaaUser(scimUser.getId(), scimUser.getUserName(), "N/A", scimUser.getPrimaryEmail(), null,
            scimUser.getGivenName(),
            scimUser.getFamilyName(), today, today,
            scimUser.getOrigin(), scimUser.getExternalId(), scimUser.isVerified(), scimUser.getZoneId(), scimUser.getSalt(),
            scimUser.getPasswordLastModified());
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher publisher) {
        this.publisher = publisher;
    }

    protected void publish(ApplicationEvent event) {
        if (publisher!=null) {
            publisher.publishEvent(event);
        }
    }

    @Override
    public PasswordPolicy getPasswordPolicy() {
        return passwordValidator.getPasswordPolicy();
    }
}
