package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationTestFactory;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.UaaOauth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.client.ClientJwtCredential;
import org.cloudfoundry.identity.uaa.oauth.provider.AuthorizationRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.provider.ClientAlreadyExistsException;
import org.cloudfoundry.identity.uaa.provider.NoSuchClientException;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.StringUtils;

import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.cloudfoundry.identity.uaa.oauth.client.ClientConstants.REQUIRED_USER_GROUPS;
import static org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsModification.SECRET;
import static org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService.DEFAULT_DELETE_STATEMENT;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@WithDatabaseContext
class MultitenantJdbcClientDetailsServiceTests {
    private MultitenantJdbcClientDetailsService service;

    private static final String SELECT_SQL = "select client_id, client_secret, client_jwt_config, resource_ids, scope, authorized_grant_types, web_server_redirect_uri, authorities, access_token_validity, refresh_token_validity, lastmodified, required_user_groups from oauth_client_details where client_id=?";

    private static final String INSERT_SQL = "insert into oauth_client_details (client_id, client_secret, client_jwt_config, resource_ids, scope, authorized_grant_types, web_server_redirect_uri, authorities, access_token_validity, refresh_token_validity, autoapprove, identity_zone_id, lastmodified, required_user_groups) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?,?)";

    private AlphanumericRandomValueStringGenerator randomValueStringGenerator;

    private String dbRequestedUserGroups = "uaa.user,uaa.something";
    private UaaClientDetails baseClientDetails;
    private JdbcTemplate spyJdbcTemplate;
    private NamedParameterJdbcTemplate spyNamedJdbcTemplate;
    private IdentityZoneManager mockIdentityZoneManager;
    private String currentZoneId;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private NamedParameterJdbcTemplate namedJdbcTemplate;

    @BeforeEach
    void setup() {
        randomValueStringGenerator = new AlphanumericRandomValueStringGenerator();
        jdbcTemplate.update("DELETE FROM oauth_client_details");
        SecurityContextHolder.getContext().setAuthentication(mock(Authentication.class));
        spyNamedJdbcTemplate = spy(namedJdbcTemplate);
        spyJdbcTemplate = spy(jdbcTemplate);
        mockIdentityZoneManager = mock(IdentityZoneManager.class);
        currentZoneId = "currentZoneId-" + randomValueStringGenerator.generate();
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(currentZoneId);
        when(spyNamedJdbcTemplate.getJdbcTemplate()).thenReturn(spyJdbcTemplate);
        service = spy(new MultitenantJdbcClientDetailsService(spyNamedJdbcTemplate, mockIdentityZoneManager, passwordEncoder));

        baseClientDetails = new UaaClientDetails();
        String clientId = "client-with-id-" + new AlphanumericRandomValueStringGenerator(36).generate();
        baseClientDetails.setClientId(clientId);
    }

    @Test
    void eventCallsDeleteMethod() {
        ClientDetails client = addClientToDb(randomValueStringGenerator.generate(), service);
        service.onApplicationEvent(new EntityDeletedEvent<>(client, mock(UaaAuthentication.class), currentZoneId));
        verify(service, times(1)).deleteByClient(eq(client.getClientId()), eq(currentZoneId));
    }

    @Test
    void deleteByClientId() {
        //this test ensures that one method calls the other, rather than having its own implementation
        for (String zoneId : Arrays.asList(OriginKeys.UAA, "zone1", "other-zone")) {
            when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(zoneId);
            try {
                service.removeClientDetails("some-client-id");
            } catch (Exception ignored) {
            }
            verify(service, times(1)).deleteByClient(eq("some-client-id"), eq(zoneId));
            reset(service);
        }
    }

    @Test
    void deleteByClientRespectsZoneIdParam() {
        //this test ensures that one method calls the other, rather than having its own implementation
        for (String zoneId : Arrays.asList(OriginKeys.UAA, "zone1", "other-zone")) {
            reset(service);
            reset(spyJdbcTemplate);
            doReturn(1).when(spyJdbcTemplate).update(anyString(), anyString(), anyString());
            when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(zoneId);
            try {
                service.deleteByClient("some-client-id", "zone-id");
            } catch (Exception ignored) {
            }
            verify(service, times(1)).deleteByClient(eq("some-client-id"), eq("zone-id"));
            verify(spyJdbcTemplate, times(1)).update(DEFAULT_DELETE_STATEMENT, "some-client-id", "zone-id");
        }
    }

    @Test
    void deleteByClientIdAndZone() {
        List<ClientDetails> defaultZoneClients = new LinkedList<>();
        addClientsInCurrentZone(defaultZoneClients, 5);
        for (String zoneId : Arrays.asList(OriginKeys.UAA, "zone1", "other-zone")) {
            when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(zoneId);

            List<ClientDetails> clients = new LinkedList<>();
            addClientsInCurrentZone(clients, 10);
            assertThat(countClientsInZone(zoneId, jdbcTemplate)).isEqualTo(clients.size());


            clients.removeIf(
                    client -> {
                        assertThat(service.deleteByClient(client.getClientId(), zoneId)).as("We deleted exactly one row").isOne();
                        assertThat(countClientsInZone(zoneId, jdbcTemplate)).as("Our client count decreased by 1").isEqualTo((clients.size() - 1));
                        assertThat(clientExists(client.getClientId(), zoneId, jdbcTemplate)).as("Client " + client.getClientId() + " was deleted.").isFalse();
                        return true;
                    });

            assertThat(clients).isEmpty();
            assertThat(countClientsInZone(zoneId, jdbcTemplate)).isZero();
        }
    }

    private void addClientsInCurrentZone(List<ClientDetails> clients, int count) {
        for (int i = 0; i < count; i++) {
            clients.add(addClientToDb(i + "-" + randomValueStringGenerator.generate(), service));
        }
    }

    @Test
    void canDeleteZoneClients() {
        String id = randomValueStringGenerator.generate();
        for (String zoneId : Arrays.asList(OriginKeys.UAA, "other-zone")) {
            when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(zoneId);
            addClientToDb(id, service);
            assertThat(countClientsInZone(zoneId, jdbcTemplate)).isOne();
        }

        IdentityZone mockIdentityZone = mock(IdentityZone.class);
        when(mockIdentityZone.getId()).thenReturn("other-zone");
        service.onApplicationEvent(new EntityDeletedEvent<>(mockIdentityZone, null, currentZoneId));
        assertThat(countClientsInZone("other-zone", jdbcTemplate)).isZero();
    }

    @Test
    void cannotDeleteUaaZoneClients() {
        String clientId = randomValueStringGenerator.generate();
        String zoneId = OriginKeys.UAA;
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(zoneId);
        addClientToDb(clientId, service);
        assertThat(countClientsInZone(zoneId, jdbcTemplate)).isOne();

        IdentityZone mockIdentityZone = mock(IdentityZone.class);
        when(mockIdentityZone.isUaa()).thenReturn(true);

        service.onApplicationEvent(new EntityDeletedEvent<>(mockIdentityZone, null, currentZoneId));
        assertThat(countClientsInZone(zoneId, jdbcTemplate)).isOne();
    }

    @Test
    void loadingClientForNonExistingClientId() {
        assertThatExceptionOfType(NoSuchClientException.class).isThrownBy(() -> service.loadClientByClientId("nonExistingClientId"));
    }

    @Test
    void loadingClientIdWithNoDetails() {
        int rowsInserted = jdbcTemplate.update(INSERT_SQL,
                "clientIdWithNoDetails", null, null,
                null, null, null, null, null, null, null,
                null, currentZoneId,
                new Timestamp(System.currentTimeMillis()),
                dbRequestedUserGroups
        );

        assertThat(rowsInserted).isOne();

        ClientDetails clientDetails = service
                .loadClientByClientId("clientIdWithNoDetails");

        assertThat(clientDetails.getClientId()).isEqualTo("clientIdWithNoDetails");
        assertThat(clientDetails.isSecretRequired()).isFalse();
        assertThat(clientDetails.getClientSecret()).isNull();
        assertThat(clientDetails.isScoped()).isFalse();
        assertThat(clientDetails.getScope()).isEmpty();
        assertThat(clientDetails.getAuthorizedGrantTypes()).hasSize(2);
        assertThat(clientDetails.getRegisteredRedirectUri()).isNull();
        assertThat(clientDetails.getAuthorities()).isEmpty();
        assertThat(clientDetails.getAccessTokenValiditySeconds()).isNull();
    }

    @Test
    void loadingClientIdWithAdditionalInformation() {

        long time = System.currentTimeMillis();
        time = time - (time % 1000);
        Timestamp lastModifiedDate = new Timestamp(time);

        jdbcTemplate.update(INSERT_SQL,
                "clientIdWithAddInfo", null, null,
                null, null, null, null, null, null, null,
                null, currentZoneId, lastModifiedDate,
                dbRequestedUserGroups);
        jdbcTemplate
                .update("update oauth_client_details set additional_information=? where client_id=?",
                        "{\"foo\":\"bar\"}", "clientIdWithAddInfo");

        ClientDetails clientDetails = service
                .loadClientByClientId("clientIdWithAddInfo");

        assertThat(clientDetails.getClientId()).isEqualTo("clientIdWithAddInfo");

        Map<String, Object> additionalInfoMap = new HashMap<>();
        additionalInfoMap.put("foo", "bar");
        additionalInfoMap.put("lastModified", lastModifiedDate);
        additionalInfoMap.put(REQUIRED_USER_GROUPS, StringUtils.commaDelimitedListToSet(dbRequestedUserGroups));

        assertThat(clientDetails.getAdditionalInformation()).containsEntry("lastModified", lastModifiedDate)
                .isEqualTo(additionalInfoMap);
    }

    @Test
    void autoApproveOnlyReturnedInField_andNotInAdditionalInfo() {
        Timestamp lastModifiedDate = new Timestamp(System.currentTimeMillis());

        String clientId = "client-with-autoapprove";
        jdbcTemplate.update(INSERT_SQL, clientId, null, null,
                null, null, null, null, null, null, null, "foo.read", currentZoneId, lastModifiedDate, dbRequestedUserGroups);
        jdbcTemplate
                .update("update oauth_client_details set additional_information=? where client_id=?",
                        "{\"autoapprove\":[\"bar.read\"]}", clientId);
        UaaClientDetails clientDetails = (UaaClientDetails) service
                .loadClientByClientId(clientId);

        assertThat(clientDetails.getClientId()).isEqualTo(clientId);
        assertThat(clientDetails.getAdditionalInformation()).doesNotContainKey(ClientConstants.AUTO_APPROVE);
        assertThat(clientDetails.getAutoApproveScopes()).contains("foo.read", "bar.read");

        jdbcTemplate
                .update("update oauth_client_details set additional_information=? where client_id=?",
                        "{\"autoapprove\":true}", clientId);
        clientDetails = (UaaClientDetails) service
                .loadClientByClientId(clientId);
        assertThat(clientDetails.getAdditionalInformation()).doesNotContainKey(ClientConstants.AUTO_APPROVE);
        assertThat(clientDetails.getAutoApproveScopes()).contains("true");
    }

    @Test
    void loadingClientIdWithSingleDetails() {
        jdbcTemplate.update(INSERT_SQL,
                "clientIdWithSingleDetails",
                "mySecret",
                "myClientJwtConfig",
                "myResource",
                "myScope",
                "myAuthorizedGrantType",
                "myRedirectUri",
                "myAuthority", 100, 200, "true",
                currentZoneId,
                new Timestamp(System.currentTimeMillis()),
                dbRequestedUserGroups);

        ClientDetails clientDetails = service
                .loadClientByClientId("clientIdWithSingleDetails");

        assertThat(clientDetails).isNotNull()
                .isInstanceOf(UaaClientDetails.class);

        UaaClientDetails uaaUaaClientDetails = (UaaClientDetails) clientDetails;
        assertThat(uaaUaaClientDetails.getClientId()).isEqualTo("clientIdWithSingleDetails");
        assertThat(uaaUaaClientDetails.isSecretRequired()).isTrue();
        assertThat(uaaUaaClientDetails.getClientSecret()).isEqualTo("mySecret");
        assertThat(uaaUaaClientDetails.isScoped()).isTrue();
        assertThat(uaaUaaClientDetails.getScope()).hasSize(1);
        assertThat(uaaUaaClientDetails.getScope().iterator().next()).isEqualTo("myScope");
        assertThat(uaaUaaClientDetails.getResourceIds()).hasSize(1);
        assertThat(uaaUaaClientDetails.getResourceIds().iterator().next()).isEqualTo("myResource");
        assertThat(uaaUaaClientDetails.getAuthorizedGrantTypes()).hasSize(1);
        assertThat(uaaUaaClientDetails.getAuthorizedGrantTypes().iterator().next()).isEqualTo("myAuthorizedGrantType");
        assertThat(uaaUaaClientDetails.getRegisteredRedirectUri().iterator().next()).isEqualTo("myRedirectUri");
        assertThat(uaaUaaClientDetails.getAuthorities()).hasSize(1);
        assertThat(uaaUaaClientDetails.getAuthorities().iterator().next().getAuthority()).isEqualTo("myAuthority");
        assertThat(uaaUaaClientDetails.getAccessTokenValiditySeconds()).isEqualTo(Integer.valueOf(100));
        assertThat(uaaUaaClientDetails.getRefreshTokenValiditySeconds()).isEqualTo(Integer.valueOf(200));
    }

    @Test
    void loadGroupsGeneratesEmptyCollection() {
        for (String s : Arrays.asList(null, "")) {
            String clientId = "clientId-" + new AlphanumericRandomValueStringGenerator().generate();
            jdbcTemplate.update(INSERT_SQL,
                    clientId,
                    "mySecret",
                    "myClientJwtConfig",
                    "myResource",
                    "myScope",
                    "myAuthorizedGrantType",
                    "myRedirectUri",
                    "myAuthority",
                    100,
                    200,
                    "true",
                    currentZoneId,
                    new Timestamp(System.currentTimeMillis()),
                    s);
            ClientDetails updatedClient = service.loadClientByClientId(clientId);
            Object userGroups = updatedClient.getAdditionalInformation().get(REQUIRED_USER_GROUPS);
            assertThat(userGroups).isNotNull()
                    .isInstanceOf(Collection.class);
            assertThat(((Collection) userGroups)).isEmpty();
        }
    }

    @Test
    void additionalInformationDoesNotOverrideUserGroupColumn() {
        String[] groups = {"group1", "group2"};
        List<String> requiredGroups = Arrays.asList(groups);
        baseClientDetails.addAdditionalInformation(REQUIRED_USER_GROUPS, requiredGroups);
        service.addClientDetails(baseClientDetails);
        assertThat(jdbcTemplate.update("UPDATE oauth_client_details SET additional_information = ? WHERE client_id = ?", JsonUtils.writeValueAsString(baseClientDetails.getAdditionalInformation()), baseClientDetails.getClientId())).isOne();
        assertThat(jdbcTemplate.update("UPDATE oauth_client_details SET required_user_groups = ? WHERE client_id = ?", "group1,group2,group3", baseClientDetails.getClientId())).isOne();
        ClientDetails updateClient = service.loadClientByClientId(baseClientDetails.getClientId());
        assertThat((Collection<String>) updateClient.getAdditionalInformation().get(REQUIRED_USER_GROUPS)).containsExactlyInAnyOrder("group1", "group2", "group3");
    }

    @Test
    void createSetsRequiredUserGroups() {
        String[] groups = {"group1", "group2"};
        List<String> requiredGroups = Arrays.asList(groups);
        baseClientDetails.addAdditionalInformation(REQUIRED_USER_GROUPS, requiredGroups);
        service.addClientDetails(baseClientDetails);
        validateRequiredGroups(baseClientDetails.getClientId(), jdbcTemplate, groups);

        groups = new String[]{"group1", "group2", "group3"};
        requiredGroups = Arrays.asList(groups);
        baseClientDetails.addAdditionalInformation(REQUIRED_USER_GROUPS, requiredGroups);
        service.updateClientDetails(baseClientDetails);
        validateRequiredGroups(baseClientDetails.getClientId(), jdbcTemplate, groups);
    }

    @Test
    void loadingClientIdWithMultipleDetails() {
        jdbcTemplate.update(INSERT_SQL,
                "clientIdWithMultipleDetails",
                "mySecret",
                "myClientJwtConfig",
                "myResource1,myResource2",
                "myScope1,myScope2",
                "myAuthorizedGrantType1,myAuthorizedGrantType2",
                "myRedirectUri1,myRedirectUri2",
                "myAuthority1,myAuthority2",
                100,
                200,
                "read,write",
                currentZoneId,
                new Timestamp(System.currentTimeMillis()),
                dbRequestedUserGroups);

        ClientDetails clientDetails = service
                .loadClientByClientId("clientIdWithMultipleDetails");

        assertThat(clientDetails.getAdditionalInformation()).isNotNull();
        Object requiredUserGroups = clientDetails.getAdditionalInformation().get(REQUIRED_USER_GROUPS);
        assertThat(requiredUserGroups).isInstanceOf(Collection.class);
        assertThat((Collection<String>) requiredUserGroups).containsExactlyInAnyOrder("uaa.user", "uaa.something");

        assertThat(clientDetails.getClientId()).isEqualTo("clientIdWithMultipleDetails");
        assertThat(clientDetails.isSecretRequired()).isTrue();
        assertThat(clientDetails.getClientSecret()).isEqualTo("mySecret");
        assertThat(clientDetails.isScoped()).isTrue();
        assertThat(clientDetails.getResourceIds()).hasSize(2);
        Iterator<String> resourceIds = clientDetails.getResourceIds()
                .iterator();
        assertThat(resourceIds.next()).isEqualTo("myResource1");
        assertThat(resourceIds.next()).isEqualTo("myResource2");
        assertThat(clientDetails.getScope()).hasSize(2);
        Iterator<String> scope = clientDetails.getScope().iterator();
        assertThat(scope.next()).isEqualTo("myScope1");
        assertThat(scope.next()).isEqualTo("myScope2");
        assertThat(clientDetails.getAuthorizedGrantTypes()).hasSize(2);
        Iterator<String> grantTypes = clientDetails.getAuthorizedGrantTypes()
                .iterator();
        assertThat(grantTypes.next()).isEqualTo("myAuthorizedGrantType1");
        assertThat(grantTypes.next()).isEqualTo("myAuthorizedGrantType2");
        assertThat(clientDetails.getRegisteredRedirectUri()).hasSize(2);
        Iterator<String> redirectUris = clientDetails
                .getRegisteredRedirectUri().iterator();
        assertThat(redirectUris.next()).isEqualTo("myRedirectUri1");
        assertThat(redirectUris.next()).isEqualTo("myRedirectUri2");
        assertThat(clientDetails.getAuthorities()).hasSize(2);
        Iterator<GrantedAuthority> authorities = clientDetails.getAuthorities()
                .iterator();
        assertThat(authorities.next().getAuthority()).isEqualTo("myAuthority1");
        assertThat(authorities.next().getAuthority()).isEqualTo("myAuthority2");
        assertThat(clientDetails.getAccessTokenValiditySeconds()).isEqualTo(Integer.valueOf(100));
        assertThat(clientDetails.getRefreshTokenValiditySeconds()).isEqualTo(Integer.valueOf(200));
        assertThat(clientDetails.isAutoApprove("read")).isTrue();
    }

    @Test
    void addClientWithNoDetails() {

        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("addedClientIdWithNoDetails");

        service.addClientDetails(clientDetails);

        Map<String, Object> map = jdbcTemplate.queryForMap(SELECT_SQL,
                "addedClientIdWithNoDetails");

        assertThat(map).containsEntry("client_id", "addedClientIdWithNoDetails")
                .containsEntry("client_secret", null);
    }

    @Test
    void addClientWithSalt() {
        String id = "addedClientIdWithSalt";
        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId(id);
        clientDetails.setClientSecret("secret");
        clientDetails.addAdditionalInformation(ClientConstants.TOKEN_SALT, "salt");
        service.addClientDetails(clientDetails);
        clientDetails = (UaaClientDetails) service.loadClientByClientId(id);
        assertThat(clientDetails).isNotNull();
        assertThat(clientDetails.getAdditionalInformation()).containsEntry(ClientConstants.TOKEN_SALT, "salt");

        clientDetails.addAdditionalInformation(ClientConstants.TOKEN_SALT, "newsalt");
        service.updateClientDetails(clientDetails);
        clientDetails = (UaaClientDetails) service.loadClientByClientId(id);
        assertThat(clientDetails).isNotNull();
        assertThat(clientDetails.getAdditionalInformation()).containsEntry(ClientConstants.TOKEN_SALT, "newsalt");
    }

    @Test
    void insertDuplicateClient() {

        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("duplicateClientIdWithNoDetails");

        service.addClientDetails(clientDetails);
        assertThatExceptionOfType(ClientAlreadyExistsException.class).isThrownBy(() -> service.addClientDetails(clientDetails));
    }

    @Test
    void updateClientSecret() {
        final String newClientSecret = "newClientSecret-" + randomValueStringGenerator.generate();
        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("newClientIdWithNoDetails");
        service.addClientDetails(clientDetails);
        service.updateClientSecret(clientDetails.getClientId(), newClientSecret);

        Map<String, Object> map = jdbcTemplate.queryForMap(SELECT_SQL,
                "newClientIdWithNoDetails");

        assertThat(map).containsEntry("client_id", "newClientIdWithNoDetails")
                .containsKey("client_secret");
        assertThat(passwordEncoder.matches(newClientSecret, (String) map.get("client_secret"))).isTrue();
    }

    @Test
    void deleteClientSecret() {
        String clientId = "client_id_test_delete";
        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId(clientId);
        clientDetails.setClientSecret(SECRET);
        service.addClientDetails(clientDetails);
        service.addClientSecret(clientId, "new_secret", currentZoneId);

        Map<String, Object> map = jdbcTemplate.queryForMap(SELECT_SQL, clientId);
        String clientSecretBeforeDelete = (String) map.get("client_secret");
        assertThat(clientSecretBeforeDelete).isNotNull();
        assertThat(clientSecretBeforeDelete.split(" ")).hasSize(2);
        service.deleteClientSecret(clientId, currentZoneId);

        map = jdbcTemplate.queryForMap(SELECT_SQL, clientId);
        String clientSecret = (String) map.get("client_secret");
        assertThat(clientSecret).isNotNull();
        assertThat(clientSecret.split(" ")).hasSize(1);
        assertThat(clientSecret).isEqualTo(clientSecretBeforeDelete.split(" ")[1]);
    }

    @Test
    void updateClientJwt() {
        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("newClientIdWithNoDetails");
        service.addClientDetails(clientDetails);
        service.addClientJwtConfig(clientDetails.getClientId(), "http://localhost:8080/uaa/token_keys", currentZoneId, true);

        Map<String, Object> map = jdbcTemplate.queryForMap(SELECT_SQL,
                "newClientIdWithNoDetails");

        assertThat(map).containsEntry("client_id", "newClientIdWithNoDetails")
                .containsKey("client_jwt_config");
        assertThat((String) map.get("client_jwt_config")).isEqualTo("{\"jwks_uri\":\"http://localhost:8080/uaa/token_keys\"}");
    }

    @Test
    void updateFederatedClientJwt() {
        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("newClientIdWithNoDetails");
        service.addClientDetails(clientDetails);
        service.addClientJwtCredential(clientDetails.getClientId(), new ClientJwtCredential("subject", "issuer", null), currentZoneId, true);

        Map<String, Object> map = jdbcTemplate.queryForMap(SELECT_SQL,
                "newClientIdWithNoDetails");

        assertThat(map).containsEntry("client_id", "newClientIdWithNoDetails")
                .containsKey("client_jwt_config")
                .containsEntry("client_jwt_config", "{\"jwt_creds\":[{\"sub\":\"subject\",\"iss\":\"issuer\"}]}");
    }

    @Test
    void deleteFederatedClientJwt() {
        String clientId = "client_id_test_delete";
        ClientJwtCredential jwtCredential = new ClientJwtCredential("subject", "issuer", "audience");
        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId(clientId);
        service.addClientDetails(clientDetails);
        service.addClientJwtCredential(clientDetails.getClientId(), jwtCredential, currentZoneId, true);

        Map<String, Object> map = jdbcTemplate.queryForMap(SELECT_SQL, clientId);
        assertThat(map).containsKey("client_jwt_config")
                .containsEntry("client_jwt_config", "{\"jwt_creds\":[{\"sub\":\"subject\",\"iss\":\"issuer\",\"aud\":\"audience\"}]}");
        service.deleteClientJwtCredential(clientId, jwtCredential, currentZoneId);

        map = jdbcTemplate.queryForMap(SELECT_SQL, clientId);
        assertThat(map).containsEntry("client_jwt_config", null)
                .doesNotContainValue("client_jwt_config");
    }

    @Test
    void deleteClientSecretForInvalidClient() {
        assertThatThrownBy(() -> service.deleteClientSecret("invalid_client_id", currentZoneId))
                .isInstanceOf(NoSuchClientException.class)
                .hasMessageContaining("No client with requested id: invalid_client_id");
    }

    @Test
    void updateClientJwtConfig() {
        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("newClientIdWithClientJwtConfig");
        clientDetails.setClientJwtConfig("small");
        service.addClientDetails(clientDetails, mockIdentityZoneManager.getCurrentIdentityZoneId());

        Map<String, Object> map = jdbcTemplate.queryForMap(SELECT_SQL,
                "newClientIdWithClientJwtConfig");
        assertThat((String) map.get("client_jwt_config")).isEqualTo("small");

        service.updateClientJwtConfig(clientDetails.getClientId(), "any json web key config", mockIdentityZoneManager.getCurrentIdentityZoneId());

        map = jdbcTemplate.queryForMap(SELECT_SQL,
                "newClientIdWithClientJwtConfig");

        assertThat(map).containsEntry("client_id", "newClientIdWithClientJwtConfig")
                .containsKey("client_jwt_config");
        assertThat((String) map.get("client_jwt_config")).isEqualTo("any json web key config");
    }

    @Test
    void updateClientRedirectURI() {

        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("newClientIdWithNoDetails");

        service.addClientDetails(clientDetails);

        String[] redirectURI = {"http://localhost:8080",
                "http://localhost:9090"};
        clientDetails.setRegisteredRedirectUri(new HashSet<>(Arrays
                .asList(redirectURI)));

        service.updateClientDetails(clientDetails);

        Map<String, Object> map = jdbcTemplate.queryForMap(SELECT_SQL,
                "newClientIdWithNoDetails");

        assertThat(map).containsEntry("client_id", "newClientIdWithNoDetails")
                .containsKey("web_server_redirect_uri")
                .containsEntry("web_server_redirect_uri", "http://localhost:8080,http://localhost:9090");
    }

    @Test
    void updateNonExistentClient() {

        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("nosuchClientIdWithNoDetails");

        assertThatExceptionOfType(NoSuchClientException.class).isThrownBy(() -> service.updateClientDetails(clientDetails));
    }

    @Test
    void removeClient() {

        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("deletedClientIdWithNoDetails");

        service.addClientDetails(clientDetails);
        service.removeClientDetails(clientDetails.getClientId());

        int count = jdbcTemplate.queryForObject(
                "select count(*) from oauth_client_details where client_id=?",
                Integer.class, "deletedClientIdWithNoDetails");
        assertThat(count).isZero();
    }

    @Test
    void removeNonExistentClient() {

        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("nosuchClientIdWithNoDetails");

        assertThatExceptionOfType(NoSuchClientException.class).isThrownBy(() -> service.removeClientDetails(clientDetails.getClientId()));
    }

    @Test
    void findClients() {

        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("aclient");

        service.addClientDetails(clientDetails);
        int count = service.listClientDetails().size();
        assertThat(count).isOne();
    }

    @Test
    void loadingClientInOtherZoneFromOtherZone() {
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn("other-zone");

        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("clientInOtherZone");
        service.addClientDetails(clientDetails);
        assertThat(service.loadClientByClientId("clientInOtherZone")).isNotNull();
    }

    @Test
    void loadingClientInOtherZoneFromDefaultZoneFails() {
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn("other-zone");
        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("clientInOtherZone");
        service.addClientDetails(clientDetails);
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(IdentityZone.getUaaZoneId());
        assertThatExceptionOfType(NoSuchClientException.class).isThrownBy(() -> service.loadClientByClientId("clientInOtherZone"));
    }

    @Test
    void addingClientToOtherIdentityZoneShouldHaveOtherIdentityZoneId() {
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn("other-zone");
        UaaClientDetails clientDetails = new UaaClientDetails();
        String clientId = "clientInOtherZone";
        clientDetails.setClientId(clientId);
        service.addClientDetails(clientDetails);
        String identityZoneId = jdbcTemplate.queryForObject("select identity_zone_id from oauth_client_details where client_id = ?", String.class, clientId);
        assertThat(identityZoneId.trim()).isEqualTo("other-zone");
    }

    @Test
    void addingClientToDefaultZoneShouldHaveDefaultZoneId() {
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(IdentityZone.getUaaZoneId());
        UaaClientDetails clientDetails = new UaaClientDetails();
        String clientId = "clientInDefaultZone";
        clientDetails.setClientId(clientId);
        service.addClientDetails(clientDetails);
        String identityZoneId = jdbcTemplate.queryForObject("select identity_zone_id from oauth_client_details where client_id = ?", String.class, clientId);
        assertThat(identityZoneId.trim()).isEqualTo(IdentityZone.getUaaZoneId());
    }

    @Test
    void createdByIdInCaseOfUser() {
        String userId = "4097895b-ebc1-4732-b6e5-2c33dd2c7cd1";
        Authentication oldAuth = authenticateAsUserAndReturnOldAuth(userId);

        UaaClientDetails clientDetails = new UaaClientDetails();
        String clientId = "clientInDefaultZone";
        clientDetails.setClientId(clientId);
        service.addClientDetails(clientDetails);

        assertThat(service.getCreatedByForClientAndZone(clientId, currentZoneId)).isEqualTo(userId);

        //Restore context
        SecurityContextHolder.getContext().setAuthentication(oldAuth);
    }

    @Test
    void createdByIdInCaseOfClient() {
        String userId = "4097895b-ebc1-4732-b6e5-2c33dd2c7cd1";
        Authentication oldAuth = authenticateAsUserAndReturnOldAuth(userId);

        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("client1");
        service.addClientDetails(clientDetails);

        authenticateAsClient(currentZoneId);

        clientDetails = new UaaClientDetails();
        String clientId = "client2";
        clientDetails.setClientId(clientId);
        service.addClientDetails(clientDetails);

        assertThat(service.getCreatedByForClientAndZone(clientId, currentZoneId)).isEqualTo(userId);

        //Restore context
        SecurityContextHolder.getContext().setAuthentication(oldAuth);
    }

    @Test
    void nullCreatedById() {
        String client1 = "client1";
        String client2 = "client2";

        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId(client1);
        service.addClientDetails(clientDetails);
        assertThat(service.getCreatedByForClientAndZone(client1, currentZoneId)).isNull();

        authenticateAsClient(currentZoneId);

        clientDetails = new UaaClientDetails();
        clientDetails.setClientId(client2);
        service.addClientDetails(clientDetails);

        assertThat(service.getCreatedByForClientAndZone(client2, currentZoneId)).isNull();
    }

    private static void validateRequiredGroups(String clientId, JdbcTemplate jdbcTemplate, String... expectedGroups) {
        String requiredUserGroups = jdbcTemplate.queryForObject("select required_user_groups from oauth_client_details where client_id = ?", String.class, clientId);
        assertThat(requiredUserGroups).isNotNull();
        Collection<String> savedGroups = StringUtils.commaDelimitedListToSet(requiredUserGroups);
        assertThat(savedGroups).containsExactlyInAnyOrder(expectedGroups);
        String additionalInformation = jdbcTemplate.queryForObject("select additional_information from oauth_client_details where client_id = ?", String.class, clientId);
        for (String s : expectedGroups) {
            assertThat(additionalInformation).doesNotContain(s);
        }
    }

    private static int countClientsInZone(String zoneId, JdbcTemplate jdbcTemplate) {
        return jdbcTemplate.queryForObject("select count(*) from oauth_client_details where identity_zone_id=?", Integer.class, new Object[]{zoneId});
    }

    private static boolean clientExists(String clientId, String zoneId, JdbcTemplate jdbcTemplate) {
        return jdbcTemplate.queryForObject("select count(*) from oauth_client_details where client_id = ? and identity_zone_id=?", Integer.class, new Object[]{clientId, zoneId}) == 1;
    }

    private static ClientDetails addClientToDb(String clientId, MultitenantJdbcClientDetailsService service) {
        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId(clientId);
        clientDetails.setClientSecret("secret");
        service.addClientDetails(clientDetails);
        return service.loadClientByClientId(clientId);
    }

    private static Authentication authenticateAsUserAndReturnOldAuth(String userId) {
        Authentication authentication = new OAuth2Authentication(new AuthorizationRequest("client",
                Collections.singletonList("read")).createOAuth2Request(), UaaAuthenticationTestFactory.getAuthentication(userId, "joe",
                "joe@test.org"));
        Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();
        SecurityContextHolder.getContext().setAuthentication(authentication);
        return currentAuth;
    }

    private static void authenticateAsClient(final String currentZoneId) {
        UaaOauth2Authentication authentication = mock(UaaOauth2Authentication.class);
        when(authentication.getZoneId()).thenReturn(currentZoneId);
        when(authentication.getPrincipal()).thenReturn("client1");
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
