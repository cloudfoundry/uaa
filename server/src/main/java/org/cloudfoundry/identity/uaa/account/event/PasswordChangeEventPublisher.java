package org.cloudfoundry.identity.uaa.account.event;

import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUser.Email;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Date;
import java.util.List;

import static java.util.Optional.ofNullable;
import static org.cloudfoundry.identity.uaa.authentication.SystemAuthentication.SYSTEM_AUTHENTICATION;

/**
 * Event publisher for password changes with the resulting event type varying
 * according to the input and outcome. Can be
 * used as an aspect intercepting calls to a component that changes user
 * password.
 */
public class PasswordChangeEventPublisher implements ApplicationEventPublisherAware {

    private final IdentityZoneManager identityZoneManager;

    static final String DEFAULT_EMAIL_DOMAIN = "this-default-was-not-configured.invalid";
    private final ScimUserProvisioning dao;

    private ApplicationEventPublisher publisher;

    public PasswordChangeEventPublisher(ScimUserProvisioning provisioning, IdentityZoneManager identityZoneManager) {
        this.dao = provisioning;
        this.identityZoneManager = identityZoneManager;
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher publisher) {
        this.publisher = publisher;
    }

    public void passwordFailure(String userId, Exception e) {
        UaaUser user = getUser(userId);
        publish(new PasswordChangeFailureEvent(e.getMessage(), user, getPrincipal(), identityZoneManager.getCurrentIdentityZoneId()));
    }

    public void passwordChange(String userId) {
        publish(new PasswordChangeEvent("Password changed", getUser(userId), getPrincipal(), identityZoneManager.getCurrentIdentityZoneId()));
    }

    UaaUser getUser(String userId) {
        try {
            // If the request came in for a user by id we should be able to
            // retrieve the username
            ScimUser scimUser = dao.retrieve(userId, identityZoneManager.getCurrentIdentityZoneId());
            Date today = new Date();
            if (scimUser != null) {
                return new UaaUser(
                        scimUser.getId(),
                        scimUser.getUserName(),
                        "N/A",
                        getEmail(scimUser),
                        null,
                        scimUser.getGivenName(),
                        scimUser.getFamilyName(),
                        today,
                        today,
                        scimUser.getOrigin(),
                        scimUser.getExternalId(),
                        scimUser.isVerified(),
                        scimUser.getZoneId(),
                        scimUser.getSalt(),
                        scimUser.getPasswordLastModified());
            }
        } catch (ScimResourceNotFoundException e) {
            // ignore
        }
        return null;
    }

    String getEmail(ScimUser scimUser) {
        List<Email> emails = scimUser.getEmails();
        if (emails == null || emails.isEmpty()) {
            return scimUser.getUserName().contains("@") ? scimUser.getUserName() : scimUser.getUserName()
                    + "@" + DEFAULT_EMAIL_DOMAIN;
        }
        for (Email email : emails) {
            if (email.isPrimary()) {
                return email.getValue();
            }
        }
        return scimUser.getEmails().getFirst().getValue();
    }

    Authentication getPrincipal() {
        return ofNullable(SecurityContextHolder.getContext().getAuthentication())
                .orElse(SYSTEM_AUTHENTICATION);
    }

    private void publish(AbstractUaaEvent event) {
        if (publisher != null) {
            publisher.publishEvent(event);
        }
    }

}
