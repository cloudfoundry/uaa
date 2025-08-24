package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.token.JdbcRevocableTokenProvisioning;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableToken;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.resources.jdbc.LimitSqlAdapter;
import org.cloudfoundry.identity.uaa.resources.jdbc.SimpleSearchQueryConverter;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManagerImpl;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.oauth.client.ClientConstants.TOKEN_SALT;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

@WithDatabaseContext
public class TokenRevocationEndpointTests {

    private TokenRevocationEndpoint endpoint;
    private UaaClientDetails client;
    private MultitenantJdbcClientDetailsService clientService;

    @Autowired
    JdbcTemplate jdbcTemplate;

    @Autowired
    NamedParameterJdbcTemplate namedJdbcTemplate;

    @Autowired
    LimitSqlAdapter limitSqlAdapter;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void setupForTokenRevocation() {
        String zoneId = IdentityZoneHolder.get().getId();
        AlphanumericRandomValueStringGenerator generator = new AlphanumericRandomValueStringGenerator();
        String clientId = generator.generate().toLowerCase();
        client = new UaaClientDetails(clientId, "", "some.scopes", "client_credentials", "authorities");
        client.addAdditionalInformation(TOKEN_SALT, "pre-salt");

        IdentityZoneManager mockIdentityZoneManager = mock(IdentityZoneManager.class);
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(IdentityZone.getUaaZoneId());

        clientService = spy(new MultitenantJdbcClientDetailsService(namedJdbcTemplate, mockIdentityZoneManager, passwordEncoder));
        clientService.addClientDetails(client, zoneId);

        ScimUserProvisioning userProvisioning = new JdbcScimUserProvisioning(
                namedJdbcTemplate,
                new JdbcPagingListFactory(namedJdbcTemplate, limitSqlAdapter),
                passwordEncoder, new IdentityZoneManagerImpl(), new JdbcIdentityZoneProvisioning(jdbcTemplate), new SimpleSearchQueryConverter(), new SimpleSearchQueryConverter(), new TimeServiceImpl(), true);
        JdbcRevocableTokenProvisioning provisioning = spy(new JdbcRevocableTokenProvisioning(jdbcTemplate, limitSqlAdapter, new TimeServiceImpl()));
        endpoint = spy(new TokenRevocationEndpoint(clientService, userProvisioning, provisioning));
        ApplicationEventPublisher publisher = mock(ApplicationEventPublisher.class);
        endpoint.setApplicationEventPublisher(publisher);

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
                        .setIssuedAt(System.currentTimeMillis()),
                zoneId
        );
    }

    @AfterEach
    void cleanup() {
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.clear();
    }

    @Test
    void revokeTokensForClient() {
        assertThat(getClient().getAdditionalInformation()).containsEntry(TOKEN_SALT, "pre-salt");
        assertThat(clientTokenCount()).isOne();
        endpoint.revokeTokensForClient(client.getClientId());
        assertThat(getClient().getAdditionalInformation()).doesNotContainEntry(TOKEN_SALT, "pre-salt");
        assertThat(clientTokenCount()).isZero();
    }

    public ClientDetails getClient() {
        return clientService.loadClientByClientId(client.getClientId());
    }

    int clientTokenCount() {
        return jdbcTemplate.queryForObject("select count(*) from revocable_tokens where client_id = ?", Integer.class, client.getClientId());
    }
}
