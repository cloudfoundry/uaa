package org.cloudfoundry.identity.uaa.authentication.listener;

import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.test.MockAuthentication;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.verification.VerificationMode;

import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
public class UserAuthenticationSuccessListenerTests {

    UserAuthenticationSuccessListener listener;
    ScimUserProvisioning scimUserProvisioning;

    @Before
    public void SetUp()
    {
        scimUserProvisioning = mock(ScimUserProvisioning.class);
        listener = new UserAuthenticationSuccessListener(scimUserProvisioning);
    }

    private static UserAuthenticationSuccessEvent getEvent(UaaUserPrototype userPrototype) {
        return new UserAuthenticationSuccessEvent(new UaaUser(userPrototype), new MockAuthentication());
    }

    private static ScimUser getScimUser(UaaUser user) {
        ScimUser scimUser = new ScimUser(user.getId(), user.getUsername(), user.getGivenName(), user.getFamilyName());
        scimUser.setVerified(user.isVerified());
        return scimUser;
    }

    @Test
    public void unverifiedUserBecomesVerifiedIfTheyHaveLegacyFlag() {
        String id = "user-id";
        UserAuthenticationSuccessEvent event = getEvent(new UaaUserPrototype()
                .withId(id)
                .withUsername("testUser")
                .withEmail("test@email.com")
                .withVerified(false)
                .withLegacyVerificationBehavior(true));
        when(scimUserProvisioning.retrieve(id)).thenReturn(getScimUser(event.getUser()));

        listener.onApplicationEvent(event);

        verify(scimUserProvisioning).verifyUser(eq(id), eq(-1));
    }

    @Test
    public void unverifiedUserDoesNotBecomeVerifiedIfTheyHaveNoLegacyFlag() {
        String id = "user-id";
        UserAuthenticationSuccessEvent event = getEvent(new UaaUserPrototype()
                .withId(id)
                .withUsername("testUser")
                .withEmail("test@email.com")
                .withVerified(false));
        when(scimUserProvisioning.retrieve(id)).thenReturn(getScimUser(event.getUser()));

        listener.onApplicationEvent(event);

        verify(scimUserProvisioning, never()).verifyUser(anyString(), anyInt());
    }

}
