/*
 *  Cloud Foundry
 *  Copyright (c) [2009-2018] Pivotal Software, Inc. All Rights Reserved.
 *  <p/>
 *  This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *  You may not use this product except in compliance with the License.
 *  <p/>
 *  This product includes a number of subcomponents with
 *  separate copyright notices and license terms. Your use of these
 *  subcomponents is subject to the terms and conditions of the
 *  subcomponent's license, as noted in the LICENSE file
 */

package org.cloudfoundry.identity.uaa.authentication.listener;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.event.IdentityProviderAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.authentication.event.MfaAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.mfa.MfaChecker;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;

import org.junit.Before;
import org.junit.Test;
import org.springframework.context.ApplicationEventPublisher;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

public class AuthenticationSuccessListenerTests {

    AuthenticationSuccessListener listener;
    ScimUserProvisioning scimUserProvisioning;
    UaaAuthentication mockAuth = mock(UaaAuthentication.class);
    MfaChecker checker;
    ApplicationEventPublisher publisher;
    private String id;
    private UaaUserPrototype userPrototype;
    private UaaUser user;

    @Before
    public void setUp() {
        publisher = mock(ApplicationEventPublisher.class);
        checker = mock(MfaChecker.class);
        scimUserProvisioning = mock(ScimUserProvisioning.class);
        listener = new AuthenticationSuccessListener(scimUserProvisioning, checker);
        listener.setApplicationEventPublisher(publisher);
        id = "user-id";
        userPrototype = new UaaUserPrototype()
            .withId(id)
            .withUsername("testUser")
            .withEmail("test@email.com");
        user = new UaaUser(userPrototype);
    }

    private ScimUser getScimUser(UaaUser user) {
        ScimUser scimUser = new ScimUser(user.getId(), user.getUsername(), user.getGivenName(), user.getFamilyName());
        scimUser.setVerified(user.isVerified());
        return scimUser;
    }

    @Test
    public void unverifiedUserBecomesVerifiedIfTheyHaveLegacyFlag() {
        userPrototype
            .withVerified(false)
            .withLegacyVerificationBehavior(true);
        UserAuthenticationSuccessEvent event = getEvent();
        String zoneId = IdentityZoneHolder.get().getId();
        when(scimUserProvisioning.retrieve(id, zoneId)).thenReturn(getScimUser(event.getUser()));
        listener.onApplicationEvent(event);
        verify(scimUserProvisioning).verifyUser(eq(id), eq(-1), eq(zoneId));
    }

    public UserAuthenticationSuccessEvent getEvent() {
        user = new UaaUser(userPrototype);
        return new UserAuthenticationSuccessEvent(
            user,
            mockAuth
        );
    }

    @Test
    public void unverifiedUserDoesNotBecomeVerifiedIfTheyHaveNoLegacyFlag() {
        userPrototype.withVerified(false);
        UserAuthenticationSuccessEvent event = getEvent();
        String zoneId = IdentityZoneHolder.get().getId();
        when(scimUserProvisioning.retrieve(id, zoneId)).thenReturn(getScimUser(event.getUser()));
        listener.onApplicationEvent(event);
        verify(scimUserProvisioning, never()).verifyUser(anyString(), anyInt(), eq(zoneId));
    }

    @Test
    public void userLastUpdatedGetsCalledOnEvent() {

        UserAuthenticationSuccessEvent event = getEvent();
        when(scimUserProvisioning.retrieve(id, IdentityZoneHolder.get().getId())).thenReturn(getScimUser(event.getUser()));
        listener.onApplicationEvent(event);
        verify(scimUserProvisioning, times(1)).updateLastLogonTime(id, IdentityZoneHolder.get().getId());
    }

    @Test
    public void previousLoginIsSetOnTheAuthentication() {
        userPrototype
            .withLastLogonSuccess(123456789L);
        UserAuthenticationSuccessEvent event = getEvent();
        String zoneId = IdentityZoneHolder.get().getId();
        when(scimUserProvisioning.retrieve(this.id, zoneId)).thenReturn(getScimUser(event.getUser()));
        UaaAuthentication authentication = (UaaAuthentication) event.getAuthentication();
        listener.onApplicationEvent(event);
        verify(authentication).setLastLoginSuccessTime(123456789L);
    }

    @Test
    public void provider_authentication_success_triggers_user_authentication_success() throws Exception {
        when(checker.isMfaEnabled(any(), any())).thenReturn(false);
        IdentityProviderAuthenticationSuccessEvent event = new IdentityProviderAuthenticationSuccessEvent(
            user,
            mockAuth
        );
        listener.onApplicationEvent(event);
        verify(publisher, times(1)).publishEvent(isA(UserAuthenticationSuccessEvent.class));
    }

    @Test
    public void provider_authentication_success_does_not_trigger_user_authentication_success() throws Exception {
        when(checker.isMfaEnabled(any(), any())).thenReturn(true);
        IdentityProviderAuthenticationSuccessEvent event = new IdentityProviderAuthenticationSuccessEvent(
            user,
            mockAuth
        );
        listener.onApplicationEvent(event);
        verifyZeroInteractions(publisher);
    }

    @Test
    public void mfa_authentication_success_triggers_user_authentication_success() throws Exception {
        when(checker.isMfaEnabled(any(), any())).thenReturn(true);
        MfaAuthenticationSuccessEvent event = new MfaAuthenticationSuccessEvent(
            user,
            mockAuth,
            "mfa-type"
        );
        listener.onApplicationEvent(event);
        verify(publisher, times(1)).publishEvent(isA(UserAuthenticationSuccessEvent.class));
    }

}
