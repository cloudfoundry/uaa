/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.account;

import org.cloudfoundry.identity.uaa.account.event.PasswordChangeEvent;
import org.cloudfoundry.identity.uaa.account.event.PasswordChangeFailureEvent;
import org.cloudfoundry.identity.uaa.account.event.ResetPasswordRequestEvent;
import org.cloudfoundry.identity.uaa.authentication.InvalidCodeException;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.endpoints.PasswordChange;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.validate.PasswordValidator;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.core.io.support.ResourcePropertySource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.NoSuchClientException;

import java.sql.Timestamp;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;

import static java.util.Collections.emptyList;
import static org.springframework.http.HttpStatus.UNPROCESSABLE_ENTITY;
import static org.springframework.util.StringUtils.isEmpty;

public class UaaResetPasswordService implements ResetPasswordService, ApplicationEventPublisherAware {

    public static final int PASSWORD_RESET_LIFETIME = 30 * 60 * 1000;
    public static final String FORGOT_PASSWORD_INTENT_PREFIX = "forgot_password_for_id:";

    private final ScimUserProvisioning scimUserProvisioning;
    private final ExpiringCodeStore expiringCodeStore;
    private final PasswordValidator passwordValidator;
    private final ClientDetailsService clientDetailsService;
    private ResourcePropertySource resourcePropertySource;
    private ApplicationEventPublisher publisher;

    public UaaResetPasswordService(ScimUserProvisioning scimUserProvisioning, ExpiringCodeStore expiringCodeStore, PasswordValidator passwordValidator, ClientDetailsService clientDetailsService,
                                   ResourcePropertySource resourcePropertySource) {
        this.scimUserProvisioning = scimUserProvisioning;
        this.expiringCodeStore = expiringCodeStore;
        this.passwordValidator = passwordValidator;
        this.clientDetailsService = clientDetailsService;
        this.resourcePropertySource = resourcePropertySource;
    }

    @Override
    public ResetPasswordResponse resetPassword(ExpiringCode code, String newPassword) {
        passwordValidator.validate(newPassword);
        return changePasswordCodeAuthenticated(code, newPassword);
    }

    @Override
    public void updateLastLogonTime(String userId) {
        scimUserProvisioning.updateLastLogonTime(userId);
    }

    @Override
    public void resetUserPassword(String userId, String password) {
        if (scimUserProvisioning.checkPasswordMatches(userId, password)) {
            throw new InvalidPasswordException(resourcePropertySource.getProperty("force_password_change.same_as_old").toString(), UNPROCESSABLE_ENTITY);
        }
        passwordValidator.validate(password);
        ScimUser user = scimUserProvisioning.retrieve(userId);
        UaaUser uaaUser = getUaaUser(user);
        Authentication authentication = constructAuthentication(uaaUser);
        updatePasswordAndPublishEvent(scimUserProvisioning, uaaUser, authentication, password);
    }

    private ResetPasswordResponse changePasswordCodeAuthenticated(ExpiringCode expiringCode, String newPassword) {
        String userId;
        String userName;
        Date passwordLastModified;
        String clientId;
        String redirectUri;
        PasswordChange change;
        try {
            change = JsonUtils.readValue(expiringCode.getData(), PasswordChange.class);
        } catch (JsonUtils.JsonUtilException x) {
            throw new InvalidCodeException("invalid_code", "Sorry, your reset password link is no longer valid. Please request a new one", 422);
        }
        userId = change.getUserId();
        userName = change.getUsername();
        passwordLastModified = change.getPasswordModifiedTime();
        clientId = change.getClientId();
        redirectUri = change.getRedirectUri();

        ScimUser user = scimUserProvisioning.retrieve(userId);
        UaaUser uaaUser = getUaaUser(user);
        Authentication authentication = constructAuthentication(uaaUser);
        try {
            if (scimUserProvisioning.checkPasswordMatches(userId, newPassword)) {
                throw new InvalidPasswordException("Your new password cannot be the same as the old password.", UNPROCESSABLE_ENTITY);
            }
            if (isUserModified(user, expiringCode.getExpiresAt(), userName, passwordLastModified)) {
                throw new UaaException("Invalid password reset request.");
            }
            if (!user.isVerified()) {
                scimUserProvisioning.verifyUser(userId, -1);
            }

            updatePasswordAndPublishEvent(scimUserProvisioning, uaaUser, authentication, newPassword);

            String redirectLocation = "home";
            if (!isEmpty(clientId) && !isEmpty(redirectUri)) {
                try {
                    ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
                    Set<String> redirectUris = clientDetails.getRegisteredRedirectUri() == null ? Collections.emptySet() :
                        clientDetails.getRegisteredRedirectUri();
                    String matchingRedirectUri = UaaUrlUtils.findMatchingRedirectUri(redirectUris, redirectUri, redirectLocation);
                    if (matchingRedirectUri != null) {
                        redirectLocation = matchingRedirectUri;
                    }
                } catch (NoSuchClientException nsce) {}
            }
            return new ResetPasswordResponse(user, redirectLocation, clientId);
        } catch (Exception e) {

            publish(new PasswordChangeFailureEvent(e.getMessage(), uaaUser, authentication));
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
                throw new NotFoundException();
            } else {
                throw new ConflictException(results.get(0).getId());
            }
        }
        ScimUser scimUser = results.get(0);

        PasswordChange change = new PasswordChange(scimUser.getId(), scimUser.getUserName(), scimUser.getPasswordLastModified(), clientId, redirectUri);
        String intent = FORGOT_PASSWORD_INTENT_PREFIX+scimUser.getId();
        expiringCodeStore.expireByIntent(intent);
        ExpiringCode code = expiringCodeStore.generateCode(JsonUtils.writeValueAsString(change), new Timestamp(System.currentTimeMillis() + PASSWORD_RESET_LIFETIME), intent);
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

    private UaaAuthentication constructAuthentication(UaaUser uaaUser) {
        return new UaaAuthentication(new UaaPrincipal(uaaUser), emptyList(), null);
    }

    private void updatePasswordAndPublishEvent(ScimUserProvisioning scimUserProvisioning, UaaUser uaaUser, Authentication authentication, String newPassword){
        scimUserProvisioning.changePassword(uaaUser.getId(), null, newPassword);
        scimUserProvisioning.updatePasswordChangeRequired(uaaUser.getId(), false);
        publish(new PasswordChangeEvent("Password changed", uaaUser, authentication));
    }
}
