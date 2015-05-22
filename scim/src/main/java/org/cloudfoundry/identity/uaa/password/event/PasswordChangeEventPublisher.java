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

package org.cloudfoundry.identity.uaa.password.event;

import java.util.Date;
import java.util.List;

import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUser.Email;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Event publisher for password changes with the resulting event type varying
 * according to the input and outcome. Can be
 * used as an aspect intercepting calls to a component that changes user
 * password.
 *
 * @author Dave Syer
 *
 */
public class PasswordChangeEventPublisher implements ApplicationEventPublisherAware {

    private ScimUserProvisioning dao;

    private ApplicationEventPublisher publisher;

    public PasswordChangeEventPublisher(ScimUserProvisioning provisioning) {
        this.dao = provisioning;
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher publisher) {
        this.publisher = publisher;
    }

    public void passwordFailure(String userId, Exception e) {
        UaaUser user = getUser(userId);
        publish(new PasswordChangeFailureEvent(e.getMessage(), user, getPrincipal()));
    }

    public void passwordChange(String userId) {
        publish(new PasswordChangeEvent("Password changed", getUser(userId), getPrincipal()));
    }

    private UaaUser getUser(String userId) {
        try {
            // If the request came in for a user by id we should be able to
            // retrieve the username
            ScimUser scimUser = dao.retrieve(userId);
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
                    scimUser.getSalt());
            }
        } catch (ScimResourceNotFoundException e) {
            // ignore
        }
        return null;
    }

    private String getEmail(ScimUser scimUser) {
        List<Email> emails = scimUser.getEmails();
        if (emails == null || emails.isEmpty()) {
            return scimUser.getUserName().contains("@") ? scimUser.getUserName() : scimUser.getUserName()
                            + "@unknown.org";
        }
        for (Email email : emails) {
            if (email.isPrimary()) {
                return email.getValue();
            }
        }
        return scimUser.getEmails().get(0).getValue();
    }

    private Authentication getPrincipal() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    private void publish(AbstractUaaEvent event) {
        if (publisher != null) {
            publisher.publishEvent(event);
        }
    }

}
