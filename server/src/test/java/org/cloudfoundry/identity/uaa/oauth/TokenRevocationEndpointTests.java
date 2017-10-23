/*
 * ****************************************************************************
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
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.token.JdbcRevocableTokenProvisioning;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableToken;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.Collections;

import static org.cloudfoundry.identity.uaa.oauth.client.ClientConstants.TOKEN_SALT;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;

public class TokenRevocationEndpointTests extends JdbcTestBase {

    private TokenRevocationEndpoint endpoint;
    private RandomValueStringGenerator generator;
    private BaseClientDetails client;
    private ApplicationEventPublisher publisher;
    private MultitenantJdbcClientDetailsService clientService;

    @Before
    public void setupForTokenRevocation() throws Exception {
        String zoneId = IdentityZoneHolder.get().getId();
        generator = new RandomValueStringGenerator();
        String clientId = generator.generate().toLowerCase();
        client = new BaseClientDetails(clientId, "", "some.scopes", "client_credentials", "authorities");
        client.addAdditionalInformation(TOKEN_SALT, "pre-salt");
        clientService = spy(new MultitenantJdbcClientDetailsService(dataSource));
        clientService.addClientDetails(client);

        ScimUserProvisioning userProvisioning = new JdbcScimUserProvisioning(
            jdbcTemplate,
            new JdbcPagingListFactory(jdbcTemplate, limitSqlAdapter)
        );
        JdbcRevocableTokenProvisioning provisioning = spy(new JdbcRevocableTokenProvisioning(jdbcTemplate));
        endpoint = spy(new TokenRevocationEndpoint(clientService, userProvisioning, provisioning));
        publisher = mock(ApplicationEventPublisher.class);

        SecurityContextHolder.getContext().setAuthentication(
            new UaaOauth2Authentication(
                "token-value",
                zoneId,
                mock(OAuth2Request.class),
                new UaaAuthentication(
                    new UaaPrincipal("id", "username", "username@test.com", OriginKeys.UAA, "", zoneId),
                    Collections.emptyList(),
                    mock(UaaAuthenticationDetails.class)
                )
            )
        );

        provisioning.create(
            new RevocableToken()
                .setClientId(client.getClientId())
                .setTokenId("token-id")
                .setUserId(null)
                .setResponseType(RevocableToken.TokenType.ACCESS_TOKEN)
                .setValue("value")
                .setIssuedAt(System.currentTimeMillis())
        );
    }

    @After
    public void cleanup() throws Exception {
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.clear();
    }

    @Test
    public void revokeTokensForClient() throws Exception {
        assertEquals("pre-salt", getClient().getAdditionalInformation().get(TOKEN_SALT));
        assertEquals(1, clientTokenCount());
        endpoint.revokeTokensForClient(client.getClientId());
        assertNotEquals("pre-salt", getClient().getAdditionalInformation().get(TOKEN_SALT));
        assertEquals(0, clientTokenCount());
    }

    public ClientDetails getClient() {
        return clientService.loadClientByClientId(client.getClientId());
    }

    public int clientTokenCount() {
        return jdbcTemplate.queryForObject("select count(*) from revocable_tokens where client_id = ?", Integer.class, client.getClientId());
    }

}