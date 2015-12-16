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

import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.error.InvalidCodeException;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.password.event.PasswordChangeEvent;
import org.cloudfoundry.identity.uaa.password.event.PasswordChangeFailureEvent;
import org.cloudfoundry.identity.uaa.password.event.ResetPasswordRequestEvent;
import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.endpoints.PasswordChange;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.validate.PasswordValidator;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.web.client.RestClientException;

import java.sql.Timestamp;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import static org.springframework.http.HttpStatus.UNPROCESSABLE_ENTITY;
import static org.springframework.util.StringUtils.isEmpty;

public class UaaResetPasswordService implements ResetPasswordService, ApplicationEventPublisherAware {

    public static final int PASSWORD_RESET_LIFETIME = 30 * 60 * 1000;

    private final ScimUserProvisioning scimUserProvisioning;
    private final ExpiringCodeStore expiringCodeStore;
    private final PasswordValidator passwordValidator;
    private final ClientDetailsService clientDetailsService;
    private ApplicationEventPublisher publisher;

    public UaaResetPasswordService(ScimUserProvisioning scimUserProvisioning, ExpiringCodeStore expiringCodeStore, PasswordValidator passwordValidator, ClientDetailsService clientDetailsService) {
        this.scimUserProvisioning = scimUserProvisioning;
        this.expiringCodeStore = expiringCodeStore;
        this.passwordValidator = passwordValidator;
        this.clientDetailsService = clientDetailsService;
    }

    @Override
    public ResetPasswordResponse resetPassword(String code, String newPassword) throws InvalidPasswordException {
        try {
            passwordValidator.validate(newPassword);
            return changePasswordCodeAuthenticated(code, newPassword);
        } catch (RestClientException e) {
            throw new UaaException(e.getMessage());
        }
    }

    private ResetPasswordResponse changePasswordCodeAuthenticated(String code, String newPassword) {
        ExpiringCode expiringCode = expiringCodeStore.retrieveCode(code);
        if (expiringCode == null) {
            throw new InvalidCodeException("invalid_code", "Sorry, your reset password link is no longer valid. Please request a new one", 422);
        }
        String userId;
        String userName = null;
        Date passwordLastModified = null;
        String clientId = null;
        String redirectUri = null;
        try {
            PasswordChange change = JsonUtils.readValue(expiringCode.getData(), PasswordChange.class);
            userId = change.getUserId();
            userName = change.getUsername();
            passwordLastModified = change.getPasswordModifiedTime();
            clientId = change.getClientId();
            redirectUri = change.getRedirectUri();
        } catch (JsonUtils.JsonUtilException x) {
            userId = expiringCode.getData();
        }
        ScimUser user = scimUserProvisioning.retrieve(userId);
        try {
            if (isUserModified(user, expiringCode.getExpiresAt(), userName, passwordLastModified)) {
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

            String redirectLocation = "home";
            if (!isEmpty(clientId) && !isEmpty(redirectUri)) {
                try {
                    ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
                    Set<String> redirectUris = clientDetails.getRegisteredRedirectUri() == null ? Collections.emptySet() :
                        clientDetails.getRegisteredRedirectUri();
                    Set<Pattern> wildcards = UaaStringUtils.constructWildcards(redirectUris);
                    if (UaaStringUtils.matches(wildcards, redirectUri)) {
                        redirectLocation = redirectUri;
                    }
                } catch (NoSuchClientException e) {
                }
            }
            return new ResetPasswordResponse(user, redirectLocation, clientId);
        } catch (Exception e) {
            publish(new PasswordChangeFailureEvent(e.getMessage(), getUaaUser(user), SecurityContextHolder.getContext().getAuthentication()));
            throw e;
        }
    }

    @Override
    public ForgotPasswordInfo forgotPassword(String email, String clientId, String redirectUri) {
        String jsonEmail = JsonUtils.writeValueAsString(email);
        List<ScimUser> results = scimUserProvisioning.query("userName eq " + jsonEmail + " and origin eq \"" + OriginKeys.UAA + "\"");
        if (results.isEmpty()) {
            results = scimUserProvisioning.query("userName eq " + jsonEmail);
            if (results.isEmpty()) {
                throw new org.cloudfoundry.identity.uaa.login.NotFoundException();
            } else {
                throw new ConflictException(results.get(0).getId());
            }
        }
        ScimUser scimUser = results.get(0);

        PasswordChange change = new PasswordChange(scimUser.getId(), scimUser.getUserName(), scimUser.getPasswordLastModified(), clientId, redirectUri);
        ExpiringCode code = expiringCodeStore.generateCode(JsonUtils.writeValueAsString(change), new Timestamp(System.currentTimeMillis() + PASSWORD_RESET_LIFETIME), null);
        publish(new ResetPasswordRequestEvent(email, code.getCode(), SecurityContextHolder.getContext().getAuthentication()));
        return new ForgotPasswordInfo(scimUser.getId(), code);
    }

    private boolean isUserModified(ScimUser user, Timestamp expiresAt, String userName, Date passwordLastModified) {
        boolean modified = false;
        if (userName!=null) {
            modified = ! (userName.equals(user.getUserName()));
        }
        if (passwordLastModified != null && (!modified)) {
            modified = user.getPasswordLastModified().getTime() != passwordLastModified.getTime();
        }
        return modified;
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

    @Override
    public PasswordPolicy getPasswordPolicy() {
        return passwordValidator.getPasswordPolicy();
    }
}
