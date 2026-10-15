package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.util.beans.BackwardsCompatibleDelegatingPasswordEncoder;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@WithDatabaseContext
class ClientAdminBootstrapMultipleSecretsUpdateTests {

    @Autowired
    private JdbcTemplate jdbcTemplate;
    @Autowired
    private NamedParameterJdbcTemplate namedJdbcTemplate;
    private String autoApproveId;
    private String allowPublicId;

    private Map<String, Map<String, Object>> clients;

    @BeforeEach
    void setUpClientAdminTests() {
        RandomValueStringGenerator randomValueStringGenerator = new RandomValueStringGenerator();
        autoApproveId = "autoapprove-" + randomValueStringGenerator.generate().toLowerCase();
        allowPublicId = "public-" + randomValueStringGenerator.generate().toLowerCase();
        clients = new HashMap<>();
    }

    @Test
    void passwordHashFirstSecretDidNotChangeButSecondIsNullDuringBootstrap() throws Exception {
        /* use bcrypt password encoder because this is used in real */
        PasswordEncoder encoder = new BackwardsCompatibleDelegatingPasswordEncoder(new BCryptPasswordEncoder(10));
        IdentityZoneManager mockIdentityZoneManager = mock(IdentityZoneManager.class);
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(IdentityZone.getUaaZoneId());
        MultitenantJdbcClientDetailsService localJdbcClientDetailsService = new MultitenantJdbcClientDetailsService(namedJdbcTemplate, mockIdentityZoneManager, encoder);
        ClientMetadataProvisioning localMetadataProvisioning = new JdbcClientMetadataProvisioning(localJdbcClientDetailsService, jdbcTemplate);
        ClientAdminBootstrap localAdminBootstrap = new ClientAdminBootstrap(
                encoder,
                localJdbcClientDetailsService,
                localMetadataProvisioning,
                true,
                clients,
                Collections.singleton(autoApproveId),
                Collections.emptySet(),
                null,
                Collections.singleton(allowPublicId));

        /* setup first a client with 2 secrets */
        Map<String, Object> map = ClientAdminBootstrapTests.createClientMap("foo");
        map.put("secret", Arrays.asList("bar", "bar"));
        ClientDetails created = ClientAdminBootstrapTests.doSimpleTest(map, localAdminBootstrap, localJdbcClientDetailsService, clients);
        ClientAdminBootstrapTests.assertSet((String) map.get("redirect-uri"), null, created.getRegisteredRedirectUri(), String.class);
        ClientDetails details = localJdbcClientDetailsService.loadClientByClientId("foo");
        assertThat(details.getClientSecret()).as("Secret database field expected to have a space, since we have 2 secrets.").contains(" ");
        assertThat(encoder.matches("bar", details.getClientSecret().split(" ")[0])).as("First secret should match bar").isTrue();

        /* update now client but provide only one secret to admin bootstrap */
        ClientAdminBootstrapTests.doSimpleTest(ClientAdminBootstrapTests.createClientMap("foo"), localAdminBootstrap, localJdbcClientDetailsService, clients);
        assertThat(details.getClientSecret()).as("Secret database field expected to have a space, since we have 2 secrets.").contains(" ");
        assertThat(encoder.matches("bar", details.getClientSecret().split(" ")[0])).as("First secret should match bar").isTrue();
    }
}
