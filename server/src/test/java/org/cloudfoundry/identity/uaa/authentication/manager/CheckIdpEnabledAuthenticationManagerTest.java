/*
 * ******************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * ******************************************************************************
 */
package org.cloudfoundry.identity.uaa.authentication.manager;


import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.user.MockUaaUserDatabase;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CheckIdpEnabledAuthenticationManagerTest extends JdbcTestBase {

    private IdentityProviderProvisioning identityProviderProvisioning;
    private CheckIdpEnabledAuthenticationManager manager;
    private UsernamePasswordAuthenticationToken token;

    @Before
    public void setupAuthManager() {
        identityProviderProvisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);
        MockUaaUserDatabase userDatabase = new MockUaaUserDatabase(u -> u.withId("id").withUsername("marissa").withEmail("test@test.org").withVerified(true).withPassword("koala"));
        PasswordEncoder encoder = mock(PasswordEncoder.class);
        when(encoder.matches(anyString(),anyString())).thenReturn(true);
        AuthzAuthenticationManager authzAuthenticationManager = new AuthzAuthenticationManager(userDatabase, encoder, identityProviderProvisioning);
        authzAuthenticationManager.setOrigin(OriginKeys.UAA);
        AccountLoginPolicy mockAccountLoginPolicy = mock(AccountLoginPolicy.class);
        when(mockAccountLoginPolicy.isAllowed(any(), any())).thenReturn(true);
        authzAuthenticationManager.setAccountLoginPolicy(mockAccountLoginPolicy);

        manager = new CheckIdpEnabledAuthenticationManager(authzAuthenticationManager, OriginKeys.UAA, identityProviderProvisioning);
        token = new UsernamePasswordAuthenticationToken("marissa", "koala");
    }

    @Test
    public void testAuthenticate() {
        Authentication auth = manager.authenticate(token);
        assertNotNull(auth);
        assertTrue(auth.isAuthenticated());
    }

    @Test(expected = ProviderNotFoundException.class)
    public void testAuthenticateIdpDisabled() {
        IdentityProvider provider = identityProviderProvisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZoneHolder.get().getId());
        provider.setActive(false);
        identityProviderProvisioning.update(provider, IdentityZoneHolder.get().getId());
        manager.authenticate(token);
    }

}
