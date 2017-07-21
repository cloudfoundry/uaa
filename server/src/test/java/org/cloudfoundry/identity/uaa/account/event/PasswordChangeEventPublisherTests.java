/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/

package org.cloudfoundry.identity.uaa.account.event;

import org.cloudfoundry.identity.uaa.account.UaaPasswordTestFactory;
import org.cloudfoundry.identity.uaa.authentication.SystemAuthentication;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimUserTestFactory;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Matchers;
import org.mockito.Mockito;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import java.util.Arrays;

import static org.junit.Assert.assertSame;

public class PasswordChangeEventPublisherTests {

    private ScimUserProvisioning scimUserProvisioning = Mockito.mock(ScimUserProvisioning.class);

    private PasswordChangeEventPublisher subject = new PasswordChangeEventPublisher(scimUserProvisioning);

    private ApplicationEventPublisher publisher = Mockito.mock(ApplicationEventPublisher.class);
    private Authentication authentication;

    @Before
    public void init() {
        subject.setApplicationEventPublisher(publisher);
        authentication = new OAuth2Authentication(
            new AuthorizationRequest(
                "client",
                Arrays.asList("read")).createOAuth2Request(),
                UaaPasswordTestFactory.getAuthentication("ID", "joe", "joe@test.org")
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    @After
    public void destroy() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void testPasswordChange() {
        Mockito.when(scimUserProvisioning.retrieve("foo", IdentityZoneHolder.get().getId())).thenReturn(
                        ScimUserTestFactory.getScimUser("joe", "joe@test.org", "Joe", "Schmo"));
        subject.passwordChange("foo");
        Mockito.verify(publisher).publishEvent(Matchers.isA(PasswordChangeEvent.class));
    }

    @Test
    public void testPasswordChangeNoEmail() {
        Mockito.when(scimUserProvisioning.retrieve("foo", IdentityZoneHolder.get().getId())).thenReturn(
                        ScimUserTestFactory.getScimUser("joe", null, "Joe", "Schmo"));
        subject.passwordChange("foo");
        Mockito.verify(publisher).publishEvent(Matchers.isA(PasswordChangeEvent.class));
    }

    @Test
    public void testPasswordFailure() {
        Mockito.when(scimUserProvisioning.retrieve("foo", IdentityZoneHolder.get().getId())).thenReturn(
                        ScimUserTestFactory.getScimUser("joe", "joe@test.org", "Joe", "Schmo"));
        subject.passwordFailure("foo", new RuntimeException("planned"));
        Mockito.verify(publisher).publishEvent(Matchers.isA(PasswordChangeFailureEvent.class));
    }

    @Test
    public void testPasswordFailureNoUser() {
        Mockito.when(scimUserProvisioning.retrieve("foo", IdentityZoneHolder.get().getId())).thenThrow(new ScimResourceNotFoundException("Not found"));
        subject.passwordFailure("foo", new RuntimeException("planned"));
        Mockito.verify(publisher).publishEvent(Matchers.any(PasswordChangeFailureEvent.class));
    }

    @Test
    public void not_authenticated_returns_system_auth() throws Exception {
        assertSame(authentication, subject.getPrincipal());
        SecurityContextHolder.clearContext();
        assertSame(SystemAuthentication.SYSTEM_AUTHENTICATION, subject.getPrincipal());
    }
}
