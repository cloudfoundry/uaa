/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.client.ClientDetailsUserDetailsService;

import static org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsModification.SECRET;
import static org.junit.Assert.*;

public class UaaClientAuthenticationProviderTest extends JdbcTestBase {

    private RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private MultitenantJdbcClientDetailsService jdbcClientDetailsService;
    private ClientDetails client;
    private ClientDetailsAuthenticationProvider authenticationProvider;

    @Before
    public void setUpForClientTests() {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        jdbcClientDetailsService = new MultitenantJdbcClientDetailsService(jdbcTemplate);
        jdbcClientDetailsService.setPasswordEncoder(encoder);
        ClientDetailsUserDetailsService clientDetailsService = new ClientDetailsUserDetailsService(jdbcClientDetailsService);
        client = createClient();
        authenticationProvider = new ClientDetailsAuthenticationProvider(clientDetailsService, encoder);
    }


    public BaseClientDetails createClient() {
        BaseClientDetails details = new BaseClientDetails(generator.generate(), "", "", "client_credentials", "uaa.resource");
        details.setClientSecret(SECRET);
        jdbcClientDetailsService.addClientDetails(details);
        return details;
    }

    public UsernamePasswordAuthenticationToken getToken(String clientId, String clientSecret) {
        return new UsernamePasswordAuthenticationToken(clientId, clientSecret);
    }

    private void testClientAuthentication(Authentication a) {
        Authentication authentication = authenticationProvider.authenticate(a);
        assertNotNull(authentication);
        assertTrue(authentication.isAuthenticated());
    }


    @Test
    public void provider_authenticate_client_with_one_password() throws Exception {
        Authentication a = getToken(client.getClientId(), SECRET);
        testClientAuthentication(a);
    }


    @Test
    public void provider_authenticate_client_with_two_passwords_test_1() throws Exception {
        jdbcClientDetailsService.addClientSecret(client.getClientId(), "secret2");
        testClientAuthentication(getToken(client.getClientId(), SECRET));
    }

    @Test
    public void provider_authenticate_client_with_two_passwords_test_2() throws Exception {
        jdbcClientDetailsService.addClientSecret(client.getClientId(), "secret2");
        testClientAuthentication(getToken(client.getClientId(), "secret2"));
    }

    @Test(expected = AuthenticationException.class)
    public void provider_authenticate_client_with_two_passwords_test_3() throws Exception {
        jdbcClientDetailsService.addClientSecret(client.getClientId(), "secret2");
        testClientAuthentication(getToken(client.getClientId(), "secret3"));
    }


}