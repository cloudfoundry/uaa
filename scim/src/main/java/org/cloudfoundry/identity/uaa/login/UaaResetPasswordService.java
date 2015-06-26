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

import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.password.event.PasswordChangeEvent;
import org.cloudfoundry.identity.uaa.password.event.PasswordChangeFailureEvent;
import org.cloudfoundry.identity.uaa.password.event.ResetPasswordRequestEvent;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.endpoints.PasswordChange;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.validate.PasswordValidator;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.client.RestClientException;

import java.sql.Timestamp;
import java.util.Date;
import java.util.List;

import static org.springframework.http.HttpStatus.UNPROCESSABLE_ENTITY;

public class UaaResetPasswordService implements ResetPasswordService, ApplicationEventPublisherAware {

    public static final int PASSWORD_RESET_LIFETIME = 30 * 60 * 1000;

    private final ScimUserProvisioning scimUserProvisioning;
    private final ExpiringCodeStore expiringCodeStore;
    private final PasswordValidator passwordValidator;
    private ApplicationEventPublisher publisher;

    public UaaResetPasswordService(ScimUserProvisioning scimUserProvisioning, ExpiringCodeStore expiringCodeStore, PasswordValidator passwordValidator) {
        this.scimUserProvisioning = scimUserProvisioning;
        this.expiringCodeStore = expiringCodeStore;
        this.passwordValidator = passwordValidator;
    }

    @Override
    public ScimUser resetPassword(String code, String newPassword) throws InvalidPasswordException {
        try {
            passwordValidator.validate(newPassword);
            return changePasswordCodeAuthenticated(code, newPassword);
        } catch (RestClientException e) {
            throw new UaaException(e.getMessage());
        }
    }

    private ScimUser changePasswordCodeAuthenticated(String code, String newPassword) {
        ExpiringCode expiringCode = expiringCodeStore.retrieveCode(code);
        if (expiringCode == null) {
            throw new UaaException("Invalid password reset request.");
        }
        String userId;
        String userName = null;
        try {
            PasswordChange change = JsonUtils.readValue(expiringCode.getData(), PasswordChange.class);
            userId = change.getUserId();
            userName = change.getUsername();
        } catch (JsonUtils.JsonUtilException x) {
            userId = expiringCode.getData();
        }
        ScimUser user = scimUserProvisioning.retrieve(userId);
        try {
            if (isUserModified(user, expiringCode.getExpiresAt(), userName)) {
                throw new UaaException("Invalid password reset request.");
            }
            if (!user.isVerified()) {
                scimUserProvisioning.verifyUser(userId, -1);
            }
            if (scimUserProvisioning.checkPasswordMatches(userId, newPassword)) {
                throw new InvalidPasswordException("Your new password cannot be the same as the old password.", UNPROCESSABLE_ENTITY);
            }
            scimUserProvisioning.changePassword(userId, null, newPassword);
            publish(new PasswordChangeEvent("Password changed", getUaaUser(user), SecurityContextHolder.getContext().getAuthentication()));
            return user;
        } catch (Exception e) {
            publish(new PasswordChangeFailureEvent(e.getMessage(), getUaaUser(user), SecurityContextHolder.getContext().getAuthentication()));
            throw e;
        }
    }

    @Override
    public ForgotPasswordInfo forgotPassword(String email) {
        String jsonEmail = JsonUtils.writeValueAsString(email);
        List<ScimUser> results = scimUserProvisioning.query("userName eq " + jsonEmail + " and origin eq \"" + Origin.UAA + "\"");
        if (results.isEmpty()) {
            results = scimUserProvisioning.query("userName eq " + jsonEmail);
            if (results.isEmpty()) {
                throw new org.cloudfoundry.identity.uaa.login.NotFoundException();
            } else {
                throw new ConflictException(results.get(0).getId());
            }
        }
        ScimUser scimUser = results.get(0);
        PasswordChange change = new PasswordChange(scimUser.getId(), scimUser.getUserName());
        ExpiringCode code = expiringCodeStore.generateCode(JsonUtils.writeValueAsString(change), new Timestamp(System.currentTimeMillis() + PASSWORD_RESET_LIFETIME));
        publish(new ResetPasswordRequestEvent(email, code.getCode(), SecurityContextHolder.getContext().getAuthentication()));
        return new ForgotPasswordInfo(scimUser.getId(), code);
    }

    private boolean isUserModified(ScimUser user, Timestamp expiresAt, String userName) {
        if (userName!=null) {
            return ! userName.equals(user.getUserName());
        }
        //left over from when all we stored in the code was the user ID
        //here we will check the timestamp
        //TODO - REMOVE THIS IN FUTURE RELEASE, ALL LINKS HAVE BEEN EXPIRED (except test created ones)
        long codeCreated = expiresAt.getTime() - PASSWORD_RESET_LIFETIME;
        long userModified = user.getMeta().getLastModified().getTime();
        return (userModified > codeCreated);
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
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.publisher = applicationEventPublisher;
    }

    protected void publish(ApplicationEvent event) {
        if (publisher!=null) {
            publisher.publishEvent(event);
        }
    }
}
