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
import org.cloudfoundry.identity.uaa.provider.NoSuchClientException;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.endpoints.PasswordChange;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.validate.PasswordValidator;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.core.io.support.ResourcePropertySource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;

import java.sql.Timestamp;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;

import static java.util.Collections.emptyList;
import static org.springframework.http.HttpStatus.UNPROCESSABLE_ENTITY;
import static org.cloudfoundry.identity.uaa.util.UaaStringUtils.isEmpty;

@Service("resetPasswordService")
public class UaaResetPasswordService implements ResetPasswordService, ApplicationEventPublisherAware {

    public static final int PASSWORD_RESET_LIFETIME = 30 * 60 * 1000;
    public static final String FORGOT_PASSWORD_INTENT_PREFIX = "forgot_password_for_id:";
    private static final String FORCE_PASSWORD_CHANGE_SAME_AS_OLD = "force_password_change.same_as_old";

    private final ScimUserProvisioning scimUserProvisioning;
    private final ExpiringCodeStore expiringCodeStore;
    private final PasswordValidator passwordValidator;
    private final MultitenantClientServices clientDetailsService;
    private final ResourcePropertySource resourcePropertySource;
    private final IdentityZoneManager identityZoneManager;
    private ApplicationEventPublisher publisher;

    public UaaResetPasswordService(ScimUserProvisioning scimUserProvisioning,
            ExpiringCodeStore expiringCodeStore,
            PasswordValidator passwordValidator,
            MultitenantClientServices clientDetailsService,
            ResourcePropertySource resourcePropertySource,
            IdentityZoneManager identityZoneManager) {
        this.scimUserProvisioning = scimUserProvisioning;
        this.expiringCodeStore = expiringCodeStore;
        this.passwordValidator = passwordValidator;
        this.clientDetailsService = clientDetailsService;
        this.resourcePropertySource = resourcePropertySource;
        this.identityZoneManager = identityZoneManager;
    }

    @Override
    public ResetPasswordResponse resetPassword(ExpiringCode code, String newPassword) {
        passwordValidator.validate(newPassword);
        return changePasswordCodeAuthenticated(code, newPassword);
    }

    @Override
    public void resetUserPassword(String userId, String password) {
        if (scimUserProvisioning.checkPasswordMatches(userId, password, identityZoneManager.getCurrentIdentityZoneId())) {
            throw new InvalidPasswordException(resourcePropertySource != null && resourcePropertySource.getProperty(FORCE_PASSWORD_CHANGE_SAME_AS_OLD) != null ? resourcePropertySource.getProperty(FORCE_PASSWORD_CHANGE_SAME_AS_OLD).toString() : FORCE_PASSWORD_CHANGE_SAME_AS_OLD, UNPROCESSABLE_ENTITY);
        }
        passwordValidator.validate(password);
        ScimUser user = scimUserProvisioning.retrieve(userId, identityZoneManager.getCurrentIdentityZoneId());
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

        ScimUser user = scimUserProvisioning.retrieve(userId, identityZoneManager.getCurrentIdentityZoneId());
        UaaUser uaaUser = getUaaUser(user);
        Authentication authentication = constructAuthentication(uaaUser);
        try {
            if (scimUserProvisioning.checkPasswordMatches(userId, newPassword, identityZoneManager.getCurrentIdentityZoneId())) {
                throw new InvalidPasswordException("Your new password cannot be the same as the old password.", UNPROCESSABLE_ENTITY);
            }
            if (isUserModified(user, userName, passwordLastModified)) {
                throw new UaaException("Invalid password reset request.");
            }
            if (!user.isVerified()) {
                scimUserProvisioning.verifyUser(userId, -1, identityZoneManager.getCurrentIdentityZoneId());
            }

            updatePasswordAndPublishEvent(scimUserProvisioning, uaaUser, authentication, newPassword);

            String redirectLocation = "home";
            if (!isEmpty(clientId) && !isEmpty(redirectUri)) {
                try {
                    ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId, identityZoneManager.getCurrentIdentityZoneId());
                    Set<String> redirectUris = clientDetails.getRegisteredRedirectUri() == null ? Collections.emptySet() :
                            clientDetails.getRegisteredRedirectUri();
                    String matchingRedirectUri = UaaUrlUtils.findMatchingRedirectUri(redirectUris, redirectUri, redirectLocation);
                    if (matchingRedirectUri != null) {
                        redirectLocation = matchingRedirectUri;
                    }
                } catch (NoSuchClientException nsce) {
                }
            }
            return new ResetPasswordResponse(user, redirectLocation, clientId);
        } catch (Exception e) {

            publish(new PasswordChangeFailureEvent(e.getMessage(), uaaUser, authentication, identityZoneManager.getCurrentIdentityZoneId()));
            throw e;
        }
    }

    @Override
    public ForgotPasswordInfo forgotPassword(String username, String clientId, String redirectUri) {
        List<ScimUser> results = scimUserProvisioning.retrieveByUsernameAndOriginAndZone(username, OriginKeys.UAA, identityZoneManager.getCurrentIdentityZoneId());
        if (results.isEmpty()) {
            results = scimUserProvisioning.retrieveByUsernameAndZone(username, identityZoneManager.getCurrentIdentityZoneId());
            if (results.isEmpty()) {
                throw new NotFoundException();
            } else {
                throw new ConflictException(results.getFirst().getId(), results.getFirst().getPrimaryEmail());
            }
        }
        ScimUser scimUser = results.getFirst();

        PasswordChange change = new PasswordChange(scimUser.getId(), scimUser.getUserName(), scimUser.getPasswordLastModified(), clientId, redirectUri);
        String intent = FORGOT_PASSWORD_INTENT_PREFIX + scimUser.getId();
        expiringCodeStore.expireByIntent(intent, identityZoneManager.getCurrentIdentityZoneId());
        ExpiringCode code = expiringCodeStore.generateCode(JsonUtils.writeValueAsString(change), new Timestamp(System.currentTimeMillis() + PASSWORD_RESET_LIFETIME), intent, identityZoneManager.getCurrentIdentityZoneId());

        String email = scimUser.getPrimaryEmail();
        if (email == null) {
            email = scimUser.getUserName();
        }

        publish(new ResetPasswordRequestEvent(username, email, code.getCode(), SecurityContextHolder.getContext().getAuthentication(), identityZoneManager.getCurrentIdentityZoneId()));
        return new ForgotPasswordInfo(scimUser.getId(), email, code);
    }

    private boolean isUserModified(ScimUser user, String userName, Date passwordLastModified) {
        boolean modified = false;
        if (userName != null) {
            modified = !userName.equals(user.getUserName());
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
        if (publisher != null) {
            publisher.publishEvent(event);
        }
    }

    private UaaAuthentication constructAuthentication(UaaUser uaaUser) {
        return new UaaAuthentication(new UaaPrincipal(uaaUser), emptyList(), null);
    }

    private void updatePasswordAndPublishEvent(ScimUserProvisioning scimUserProvisioning, UaaUser uaaUser, Authentication authentication, String newPassword) {
        scimUserProvisioning.changePassword(uaaUser.getId(), null, newPassword, identityZoneManager.getCurrentIdentityZoneId());
        scimUserProvisioning.updatePasswordChangeRequired(uaaUser.getId(), false, identityZoneManager.getCurrentIdentityZoneId());
        publish(new PasswordChangeEvent("Password changed", uaaUser, authentication, identityZoneManager.getCurrentIdentityZoneId()));
    }
}
