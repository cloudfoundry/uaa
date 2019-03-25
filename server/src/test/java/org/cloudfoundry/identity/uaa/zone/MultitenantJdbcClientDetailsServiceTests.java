package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationTestFactory;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.UaaOauth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.util.StringUtils;

import java.sql.Timestamp;
import java.util.*;

import static org.cloudfoundry.identity.uaa.oauth.client.ClientConstants.REQUIRED_USER_GROUPS;
import static org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsModification.SECRET;
import static org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder.isUaa;
import static org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService.DEFAULT_DELETE_STATEMENT;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

public class MultitenantJdbcClientDetailsServiceTests extends JdbcTestBase {
    private MultitenantJdbcClientDetailsService service;

    private static final String SELECT_SQL = "select client_id, client_secret, resource_ids, scope, authorized_grant_types, web_server_redirect_uri, authorities, access_token_validity, refresh_token_validity, lastmodified, required_user_groups from oauth_client_details where client_id=?";

    private static final String INSERT_SQL = "insert into oauth_client_details (client_id, client_secret, resource_ids, scope, authorized_grant_types, web_server_redirect_uri, authorities, access_token_validity, refresh_token_validity, autoapprove, identity_zone_id, lastmodified, required_user_groups) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?)";

    private IdentityZone otherIdentityZone;

    private RandomValueStringGenerator generate = new RandomValueStringGenerator();

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    private String dbRequestedUserGroups = "uaa.user,uaa.something";
    private BaseClientDetails clientDetails;
    private JdbcTemplate template;

    @Before
    public void setup() throws Exception {
        jdbcTemplate.update("DELETE FROM oauth_client_details");
        Authentication authentication = mock(Authentication.class);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        template = spy(jdbcTemplate);
        service = spy(new MultitenantJdbcClientDetailsService(template));
        service.setPasswordEncoder(NoOpPasswordEncoder.getInstance());
        otherIdentityZone = new IdentityZone();
        otherIdentityZone.setId("testzone");
        otherIdentityZone.setName("testzone");
        otherIdentityZone.setSubdomain("testzone");

        clientDetails = new BaseClientDetails();
        String clientId = "client-with-id-" + new RandomValueStringGenerator(36).generate();
        clientDetails.setClientId(clientId);

    }

    @Test
    public void eventCallsDeleteMethod() {
        ClientDetails client = addClientToDb(generate.generate(), service);
        service.onApplicationEvent(new EntityDeletedEvent<>(client, mock(UaaAuthentication.class)));
        verify(service, times(1)).deleteByClient(eq(client.getClientId()), eq(IdentityZoneHolder.get().getId()));
    }

    @Test
    public void deleteByClientId() {
        //this test ensures that one method calls the other, rather than having its own implementation
        for (IdentityZone zone : Arrays.asList(IdentityZone.getUaa(), otherIdentityZone)) {
            IdentityZoneHolder.set(zone);
            try {
                service.removeClientDetails("some-client-id");
            } catch (Exception ignored) {
            }
            verify(service, times(1)).deleteByClient(eq("some-client-id"), eq(zone.getId()));
            reset(service);
        }
    }

    @Test
    public void deleteByClientRespectsZoneIdParam() {
        //this test ensures that one method calls the other, rather than having its own implementation
        for (IdentityZone zone : Arrays.asList(IdentityZone.getUaa(), otherIdentityZone)) {
            reset(service);
            reset(template);
            doReturn(1).when(template).update(anyString(), anyString(), anyString());
            IdentityZoneHolder.set(zone);
            try {
                service.deleteByClient("some-client-id", "zone-id");
            } catch (Exception ignored) {
            }
            verify(service, times(1)).deleteByClient(eq("some-client-id"), eq("zone-id"));
            verify(template, times(1)).update(DEFAULT_DELETE_STATEMENT, "some-client-id", "zone-id");
        }
    }

    @Test
    public void deleteByClientIdAndZone() {
        List<ClientDetails> defaultZoneClients = new LinkedList<>();
        addClientsInCurrentZone(defaultZoneClients, 5);
        for (IdentityZone zone : Arrays.asList(IdentityZone.getUaa(), otherIdentityZone)) {
            IdentityZoneHolder.set(zone);
            List<ClientDetails> clients = new LinkedList<>();
            addClientsInCurrentZone(clients, 10);
            assertEquals((isUaa() ? 5 : 0) + clients.size(), countClientsInZone(zone.getId(), jdbcTemplate));


            clients.removeIf(
                    client -> {
                        assertEquals("We deleted exactly one row", 1, service.deleteByClient(client.getClientId(), zone.getId()));
                        assertEquals("Our client count decreased by 1", (isUaa() ? 5 : 0) + (clients.size() - 1), countClientsInZone(zone.getId(), jdbcTemplate));
                        assertFalse("Client " + client.getClientId() + " was deleted.", clientExists(client.getClientId(), zone.getId(), jdbcTemplate));
                        return true;
                    });

            assertEquals(0, clients.size());
            assertEquals(isUaa() ? 5 : 0, countClientsInZone(zone.getId(), jdbcTemplate));
        }
    }

    private void addClientsInCurrentZone(List<ClientDetails> clients, int count) {
        for (int i = 0; i < count; i++) {
            clients.add(addClientToDb(i + "-" + generate.generate(), service));
        }
    }

    @Test
    public void canDeleteZoneClients() {
        String id = generate.generate();
        for (IdentityZone zone : Arrays.asList(IdentityZone.getUaa(), otherIdentityZone)) {
            IdentityZoneHolder.set(zone);
            addClientToDb(id, service);
            assertThat(countClientsInZone(IdentityZoneHolder.get().getId(), jdbcTemplate), is(1));
        }

        service.onApplicationEvent(new EntityDeletedEvent<>(otherIdentityZone, null));
        assertThat(countClientsInZone(otherIdentityZone.getId(), jdbcTemplate), is(0));
    }

    @Test
    public void cannotDeleteUaaZoneClients() {
        String id = generate.generate();
        addClientToDb(id, service);
        String zoneId = IdentityZoneHolder.get().getId();
        assertThat(countClientsInZone(zoneId, jdbcTemplate), is(1));

        service.onApplicationEvent(new EntityDeletedEvent<>(IdentityZoneHolder.get(), null));
        assertThat(countClientsInZone(zoneId, jdbcTemplate), is(1));
    }

    @Test(expected = NoSuchClientException.class)
    public void loadingClientForNonExistingClientId() {
        service.loadClientByClientId("nonExistingClientId");
    }

    @Test
    public void loadingClientIdWithNoDetails() {
        int rowsInserted = jdbcTemplate.update(INSERT_SQL,
                "clientIdWithNoDetails", null, null,
                null, null, null, null, null, null, null,
                IdentityZoneHolder.get().getId(),
                new Timestamp(System.currentTimeMillis()),
                dbRequestedUserGroups
        );

        assertEquals(1, rowsInserted);

        ClientDetails clientDetails = service
                .loadClientByClientId("clientIdWithNoDetails");

        assertEquals("clientIdWithNoDetails", clientDetails.getClientId());
        assertFalse(clientDetails.isSecretRequired());
        assertNull(clientDetails.getClientSecret());
        assertFalse(clientDetails.isScoped());
        assertEquals(0, clientDetails.getScope().size());
        assertEquals(2, clientDetails.getAuthorizedGrantTypes().size());
        assertNull(clientDetails.getRegisteredRedirectUri());
        assertEquals(0, clientDetails.getAuthorities().size());
        assertNull(clientDetails.getAccessTokenValiditySeconds());
        assertNull(clientDetails.getAccessTokenValiditySeconds());
    }

    @Test
    public void loadingClientIdWithAdditionalInformation() {

        long time = System.currentTimeMillis();
        time = time - (time % 1000);
        Timestamp lastModifiedDate = new Timestamp(time);

        jdbcTemplate.update(INSERT_SQL,
                "clientIdWithAddInfo", null, null,
                null, null, null, null, null, null, null,
                IdentityZoneHolder.get().getId(), lastModifiedDate,
                dbRequestedUserGroups);
        jdbcTemplate
                .update("update oauth_client_details set additional_information=? where client_id=?",
                        "{\"foo\":\"bar\"}", "clientIdWithAddInfo");

        ClientDetails clientDetails = service
                .loadClientByClientId("clientIdWithAddInfo");

        assertEquals("clientIdWithAddInfo", clientDetails.getClientId());

        Map<String, Object> additionalInfoMap = new HashMap<>();
        additionalInfoMap.put("foo", "bar");
        additionalInfoMap.put("lastModified", lastModifiedDate);
        additionalInfoMap.put(REQUIRED_USER_GROUPS, StringUtils.commaDelimitedListToSet(dbRequestedUserGroups));

        assertEquals(lastModifiedDate, clientDetails.getAdditionalInformation().get("lastModified"));
        assertEquals(additionalInfoMap, clientDetails.getAdditionalInformation());
    }

    @Test
    public void autoApproveOnlyReturnedInField_andNotInAdditionalInfo() {
        Timestamp lastModifiedDate = new Timestamp(System.currentTimeMillis());

        String clientId = "client-with-autoapprove";
        jdbcTemplate.update(INSERT_SQL, clientId, null, null,
                null, null, null, null, null, null, "foo.read", IdentityZoneHolder.get().getId(), lastModifiedDate, dbRequestedUserGroups);
        jdbcTemplate
                .update("update oauth_client_details set additional_information=? where client_id=?",
                        "{\"autoapprove\":[\"bar.read\"]}", clientId);
        BaseClientDetails clientDetails = (BaseClientDetails) service
                .loadClientByClientId(clientId);

        assertEquals(clientId, clientDetails.getClientId());
        assertNull(clientDetails.getAdditionalInformation().get(ClientConstants.AUTO_APPROVE));
        assertThat(clientDetails.getAutoApproveScopes(), Matchers.hasItems("foo.read", "bar.read"));

        jdbcTemplate
                .update("update oauth_client_details set additional_information=? where client_id=?",
                        "{\"autoapprove\":true}", clientId);
        clientDetails = (BaseClientDetails) service
                .loadClientByClientId(clientId);
        assertNull(clientDetails.getAdditionalInformation().get(ClientConstants.AUTO_APPROVE));
        assertThat(clientDetails.getAutoApproveScopes(), Matchers.hasItems("true"));
    }

    @Test
    public void loadingClientIdWithSingleDetails() {
        jdbcTemplate.update(INSERT_SQL,
                "clientIdWithSingleDetails",
                "mySecret",
                "myResource",
                "myScope",
                "myAuthorizedGrantType",
                "myRedirectUri",
                "myAuthority", 100, 200, "true",
                IdentityZoneHolder.get().getId(),
                new Timestamp(System.currentTimeMillis()),
                dbRequestedUserGroups);

        ClientDetails clientDetails = service
                .loadClientByClientId("clientIdWithSingleDetails");

        assertEquals("clientIdWithSingleDetails", clientDetails.getClientId());
        assertTrue(clientDetails.isSecretRequired());
        assertEquals("mySecret", clientDetails.getClientSecret());
        assertTrue(clientDetails.isScoped());
        assertEquals(1, clientDetails.getScope().size());
        assertEquals("myScope", clientDetails.getScope().iterator().next());
        assertEquals(1, clientDetails.getResourceIds().size());
        assertEquals("myResource", clientDetails.getResourceIds().iterator()
                .next());
        assertEquals(1, clientDetails.getAuthorizedGrantTypes().size());
        assertEquals("myAuthorizedGrantType", clientDetails
                .getAuthorizedGrantTypes().iterator().next());
        assertEquals("myRedirectUri", clientDetails.getRegisteredRedirectUri()
                .iterator().next());
        assertEquals(1, clientDetails.getAuthorities().size());
        assertEquals("myAuthority", clientDetails.getAuthorities().iterator()
                .next().getAuthority());
        assertEquals(new Integer(100),
                clientDetails.getAccessTokenValiditySeconds());
        assertEquals(new Integer(200),
                clientDetails.getRefreshTokenValiditySeconds());
    }

    @Test
    public void loadGroupsGeneratesEmptyCollection() {
        for (String s : Arrays.asList(null, "")) {
            String clientId = "clientId-" + new RandomValueStringGenerator().generate();
            jdbcTemplate.update(INSERT_SQL,
                    clientId,
                    "mySecret",
                    "myResource",
                    "myScope",
                    "myAuthorizedGrantType",
                    "myRedirectUri",
                    "myAuthority",
                    100,
                    200,
                    "true",
                    IdentityZoneHolder.get().getId(),
                    new Timestamp(System.currentTimeMillis()),
                    s);
            ClientDetails updatedClient = service.loadClientByClientId(clientId);
            Object userGroups = updatedClient.getAdditionalInformation().get(REQUIRED_USER_GROUPS);
            assertNotNull(userGroups);
            assertTrue(userGroups instanceof Collection);
            assertEquals(0, ((Collection) userGroups).size());
        }
    }

    @Test
    public void additionalInformationDoesNotOverrideUserGroupColumn() {
        String[] groups = {"group1", "group2"};
        List<String> requiredGroups = Arrays.asList(groups);
        clientDetails.addAdditionalInformation(REQUIRED_USER_GROUPS, requiredGroups);
        service.addClientDetails(clientDetails);
        assertEquals(1, jdbcTemplate.update("UPDATE oauth_client_details SET additional_information = ? WHERE client_id = ?", JsonUtils.writeValueAsString(clientDetails.getAdditionalInformation()), clientDetails.getClientId()));
        assertEquals(1, jdbcTemplate.update("UPDATE oauth_client_details SET required_user_groups = ? WHERE client_id = ?", "group1,group2,group3", clientDetails.getClientId()));
        ClientDetails updateClient = service.loadClientByClientId(clientDetails.getClientId());
        assertThat((Collection<String>) updateClient.getAdditionalInformation().get(REQUIRED_USER_GROUPS), containsInAnyOrder("group1", "group2", "group3"));
    }

    @Test
    public void createSetsRequiredUserGroups() {
        String[] groups = {"group1", "group2"};
        List<String> requiredGroups = Arrays.asList(groups);
        clientDetails.addAdditionalInformation(REQUIRED_USER_GROUPS, requiredGroups);
        service.addClientDetails(clientDetails);
        validateRequiredGroups(clientDetails.getClientId(), jdbcTemplate, groups);

        groups = new String[]{"group1", "group2", "group3"};
        requiredGroups = Arrays.asList(groups);
        clientDetails.addAdditionalInformation(REQUIRED_USER_GROUPS, requiredGroups);
        service.updateClientDetails(clientDetails);
        validateRequiredGroups(clientDetails.getClientId(), jdbcTemplate, groups);
    }

    @Test
    public void loadingClientIdWithMultipleDetails() {
        jdbcTemplate.update(INSERT_SQL,
                "clientIdWithMultipleDetails",
                "mySecret",
                "myResource1,myResource2",
                "myScope1,myScope2",
                "myAuthorizedGrantType1,myAuthorizedGrantType2",
                "myRedirectUri1,myRedirectUri2",
                "myAuthority1,myAuthority2",
                100,
                200,
                "read,write",
                IdentityZoneHolder.get().getId(),
                new Timestamp(System.currentTimeMillis()),
                dbRequestedUserGroups);

        ClientDetails clientDetails = service
                .loadClientByClientId("clientIdWithMultipleDetails");

        assertNotNull(clientDetails.getAdditionalInformation());
        Object requiredUserGroups = clientDetails.getAdditionalInformation().get(REQUIRED_USER_GROUPS);
        assertNotNull(requiredUserGroups);
        assertTrue(requiredUserGroups instanceof Collection);
        assertThat((Collection<String>) requiredUserGroups, containsInAnyOrder("uaa.user", "uaa.something"));

        assertEquals("clientIdWithMultipleDetails", clientDetails.getClientId());
        assertTrue(clientDetails.isSecretRequired());
        assertEquals("mySecret", clientDetails.getClientSecret());
        assertTrue(clientDetails.isScoped());
        assertEquals(2, clientDetails.getResourceIds().size());
        Iterator<String> resourceIds = clientDetails.getResourceIds()
                .iterator();
        assertEquals("myResource1", resourceIds.next());
        assertEquals("myResource2", resourceIds.next());
        assertEquals(2, clientDetails.getScope().size());
        Iterator<String> scope = clientDetails.getScope().iterator();
        assertEquals("myScope1", scope.next());
        assertEquals("myScope2", scope.next());
        assertEquals(2, clientDetails.getAuthorizedGrantTypes().size());
        Iterator<String> grantTypes = clientDetails.getAuthorizedGrantTypes()
                .iterator();
        assertEquals("myAuthorizedGrantType1", grantTypes.next());
        assertEquals("myAuthorizedGrantType2", grantTypes.next());
        assertEquals(2, clientDetails.getRegisteredRedirectUri().size());
        Iterator<String> redirectUris = clientDetails
                .getRegisteredRedirectUri().iterator();
        assertEquals("myRedirectUri1", redirectUris.next());
        assertEquals("myRedirectUri2", redirectUris.next());
        assertEquals(2, clientDetails.getAuthorities().size());
        Iterator<GrantedAuthority> authorities = clientDetails.getAuthorities()
                .iterator();
        assertEquals("myAuthority1", authorities.next().getAuthority());
        assertEquals("myAuthority2", authorities.next().getAuthority());
        assertEquals(new Integer(100),
                clientDetails.getAccessTokenValiditySeconds());
        assertEquals(new Integer(200),
                clientDetails.getRefreshTokenValiditySeconds());
        assertTrue(clientDetails.isAutoApprove("read"));
    }

    @Test
    public void addClientWithNoDetails() {

        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("addedClientIdWithNoDetails");

        service.addClientDetails(clientDetails);

        Map<String, Object> map = jdbcTemplate.queryForMap(SELECT_SQL,
                "addedClientIdWithNoDetails");

        assertEquals("addedClientIdWithNoDetails", map.get("client_id"));
        assertTrue(map.containsKey("client_secret"));
        assertNull(map.get("client_secret"));
    }

    @Test
    public void addClientWithSalt() {
        String id = "addedClientIdWithSalt";
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId(id);
        clientDetails.setClientSecret("secret");
        clientDetails.addAdditionalInformation(ClientConstants.TOKEN_SALT, "salt");
        service.addClientDetails(clientDetails);
        clientDetails = (BaseClientDetails) service.loadClientByClientId(id);
        assertNotNull(clientDetails);
        assertEquals("salt", clientDetails.getAdditionalInformation().get(ClientConstants.TOKEN_SALT));

        clientDetails.addAdditionalInformation(ClientConstants.TOKEN_SALT, "newsalt");
        service.updateClientDetails(clientDetails);
        clientDetails = (BaseClientDetails) service.loadClientByClientId(id);
        assertNotNull(clientDetails);
        assertEquals("newsalt", clientDetails.getAdditionalInformation().get(ClientConstants.TOKEN_SALT));
    }

    @Test(expected = ClientAlreadyExistsException.class)
    public void insertDuplicateClient() {

        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("duplicateClientIdWithNoDetails");

        service.addClientDetails(clientDetails);
        service.addClientDetails(clientDetails);
    }

    @Test
    public void updateClientSecret() {

        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("newClientIdWithNoDetails");

        service.setPasswordEncoder(new PasswordEncoder() {

            public boolean matches(CharSequence rawPassword,
                                   String encodedPassword) {
                return true;
            }

            public String encode(CharSequence rawPassword) {
                return "BAR";
            }
        });
        service.addClientDetails(clientDetails);
        service.updateClientSecret(clientDetails.getClientId(), "foo");

        Map<String, Object> map = jdbcTemplate.queryForMap(SELECT_SQL,
                "newClientIdWithNoDetails");

        assertEquals("newClientIdWithNoDetails", map.get("client_id"));
        assertTrue(map.containsKey("client_secret"));
        assertEquals("BAR", map.get("client_secret"));
    }

    @Test
    public void deleteClientSecret() {
        String clientId = "client_id_test_delete";
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId(clientId);
        clientDetails.setClientSecret(SECRET);
        service.addClientDetails(clientDetails);
        service.addClientSecret(clientId, "new_secret", IdentityZoneHolder.get().getId());

        Map<String, Object> map = jdbcTemplate.queryForMap(SELECT_SQL, clientId);
        String clientSecretBeforeDelete = (String) map.get("client_secret");
        assertNotNull(clientSecretBeforeDelete);
        assertEquals(2, clientSecretBeforeDelete.split(" ").length);
        service.deleteClientSecret(clientId, IdentityZoneHolder.get().getId());

        map = jdbcTemplate.queryForMap(SELECT_SQL, clientId);
        String clientSecret = (String) map.get("client_secret");
        assertNotNull(clientSecret);
        assertEquals(1, clientSecret.split(" ").length);
        assertEquals(clientSecretBeforeDelete.split(" ")[1], clientSecret);
    }

    @Test
    public void deleteClientSecretForInvalidClient() {
        expectedEx.expect(NoSuchClientException.class);
        expectedEx.expectMessage("No client with requested id: invalid_client_id");
        service.deleteClientSecret("invalid_client_id", IdentityZoneHolder.get().getId());
    }

    @Test
    public void updateClientRedirectURI() {

        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("newClientIdWithNoDetails");

        service.addClientDetails(clientDetails);

        String[] redirectURI = {"http://localhost:8080",
                "http://localhost:9090"};
        clientDetails.setRegisteredRedirectUri(new HashSet<>(Arrays
                .asList(redirectURI)));

        service.updateClientDetails(clientDetails);

        Map<String, Object> map = jdbcTemplate.queryForMap(SELECT_SQL,
                "newClientIdWithNoDetails");

        assertEquals("newClientIdWithNoDetails", map.get("client_id"));
        assertTrue(map.containsKey("web_server_redirect_uri"));
        assertEquals("http://localhost:8080,http://localhost:9090",
                map.get("web_server_redirect_uri"));
    }

    @Test(expected = NoSuchClientException.class)
    public void updateNonExistentClient() {

        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("nosuchClientIdWithNoDetails");

        service.updateClientDetails(clientDetails);
    }

    @Test
    public void removeClient() {

        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("deletedClientIdWithNoDetails");

        service.addClientDetails(clientDetails);
        service.removeClientDetails(clientDetails.getClientId());

        int count = jdbcTemplate.queryForObject(
                "select count(*) from oauth_client_details where client_id=?",
                Integer.class, "deletedClientIdWithNoDetails");

        assertEquals(0, count);
    }

    @Test(expected = NoSuchClientException.class)
    public void removeNonExistentClient() {

        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("nosuchClientIdWithNoDetails");

        service.removeClientDetails(clientDetails.getClientId());
    }

    @Test
    public void findClients() {

        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("aclient");

        service.addClientDetails(clientDetails);
        int count = service.listClientDetails().size();

        assertEquals(1, count);
    }

    @Test
    public void loadingClientInOtherZoneFromOtherZone() {
        IdentityZoneHolder.set(otherIdentityZone);
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("clientInOtherZone");
        service.addClientDetails(clientDetails);
        assertNotNull(service.loadClientByClientId("clientInOtherZone"));
    }

    @Test(expected = NoSuchClientException.class)
    public void loadingClientInOtherZoneFromDefaultZoneFails() {
        IdentityZoneHolder.set(otherIdentityZone);
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("clientInOtherZone");
        service.addClientDetails(clientDetails);
        IdentityZoneHolder.clear();
        service.loadClientByClientId("clientInOtherZone");
    }

    @Test
    public void addingClientToOtherIdentityZoneShouldHaveOtherIdentityZoneId() {
        IdentityZoneHolder.set(otherIdentityZone);
        BaseClientDetails clientDetails = new BaseClientDetails();
        String clientId = "clientInOtherZone";
        clientDetails.setClientId(clientId);
        service.addClientDetails(clientDetails);
        String identityZoneId = jdbcTemplate.queryForObject("select identity_zone_id from oauth_client_details where client_id = ?", String.class, clientId);
        assertEquals(otherIdentityZone.getId(), identityZoneId.trim());
    }

    @Test
    public void addingClientToDefaultIdentityZoneShouldHaveAnIdentityZoneId() {
        BaseClientDetails clientDetails = new BaseClientDetails();
        String clientId = "clientInDefaultZone";
        clientDetails.setClientId(clientId);
        service.addClientDetails(clientDetails);
        String identityZoneId = jdbcTemplate.queryForObject("select identity_zone_id from oauth_client_details where client_id = ?", String.class, clientId);
        assertEquals(IdentityZone.getUaaZoneId(), identityZoneId.trim());
    }

    @Test
    public void createdByIdInCaseOfUser() {
        String userId = "4097895b-ebc1-4732-b6e5-2c33dd2c7cd1";
        Authentication oldAuth = authenticateAsUserAndReturnOldAuth(userId);

        BaseClientDetails clientDetails = new BaseClientDetails();
        String clientId = "clientInDefaultZone";
        clientDetails.setClientId(clientId);
        service.addClientDetails(clientDetails);

        assertEquals(userId, service.getCreatedByForClientAndZone(clientId, OriginKeys.UAA));

        //Restore context
        SecurityContextHolder.getContext().setAuthentication(oldAuth);
    }

    @Test
    public void createdByIdInCaseOfClient() {
        String userId = "4097895b-ebc1-4732-b6e5-2c33dd2c7cd1";
        Authentication oldAuth = authenticateAsUserAndReturnOldAuth(userId);

        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("client1");
        service.addClientDetails(clientDetails);

        authenticateAsClient();

        clientDetails = new BaseClientDetails();
        String clientId = "client2";
        clientDetails.setClientId(clientId);
        service.addClientDetails(clientDetails);

        assertEquals(userId, service.getCreatedByForClientAndZone(clientId, OriginKeys.UAA));

        //Restore context
        SecurityContextHolder.getContext().setAuthentication(oldAuth);
    }

    @Test
    public void nullCreatedById() {
        Authentication authentication = mock(Authentication.class);
        when(authentication.getPrincipal()).thenReturn(null);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String client1 = "client1";
        String client2 = "client2";

        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId(client1);
        service.addClientDetails(clientDetails);
        assertNull(service.getCreatedByForClientAndZone(client1, OriginKeys.UAA));

        authenticateAsClient();

        clientDetails = new BaseClientDetails();
        clientDetails.setClientId(client2);
        service.addClientDetails(clientDetails);

        assertNull(service.getCreatedByForClientAndZone(client2, OriginKeys.UAA));
    }

    private static void validateRequiredGroups(String clientId, JdbcTemplate jdbcTemplate, String... expectedGroups) {
        String requiredUserGroups = jdbcTemplate.queryForObject("select required_user_groups from oauth_client_details where client_id = ?", String.class, clientId);
        assertNotNull(requiredUserGroups);
        Collection<String> savedGroups = StringUtils.commaDelimitedListToSet(requiredUserGroups);
        assertThat(savedGroups, containsInAnyOrder(expectedGroups));
        String additionalInformation = jdbcTemplate.queryForObject("select additional_information from oauth_client_details where client_id = ?", String.class, clientId);
        for (String s : expectedGroups) {
            assertThat(additionalInformation, not(containsString(s)));
        }
    }

    private static int countClientsInZone(String zoneId, JdbcTemplate jdbcTemplate) {
        return jdbcTemplate.queryForObject("select count(*) from oauth_client_details where identity_zone_id=?", new Object[]{zoneId}, Integer.class);
    }

    private static boolean clientExists(String clientId, String zoneId, JdbcTemplate jdbcTemplate) {
        return jdbcTemplate.queryForObject("select count(*) from oauth_client_details where client_id = ? and identity_zone_id=?", new Object[]{clientId, zoneId}, Integer.class) == 1;
    }

    private static ClientDetails addClientToDb(String id, MultitenantJdbcClientDetailsService service) {
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId(id);
        clientDetails.setClientSecret("secret");
        service.addClientDetails(clientDetails);
        return service.loadClientByClientId(id);
    }

    private static Authentication authenticateAsUserAndReturnOldAuth(String userId) {
        Authentication authentication = new OAuth2Authentication(new AuthorizationRequest("client",
                Collections.singletonList("read")).createOAuth2Request(), UaaAuthenticationTestFactory.getAuthentication(userId, "joe",
                "joe@test.org"));
        Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();
        SecurityContextHolder.getContext().setAuthentication(authentication);
        return currentAuth;
    }

    private static void authenticateAsClient() {
        UaaOauth2Authentication authentication = mock(UaaOauth2Authentication.class);
        when(authentication.getZoneId()).thenReturn(OriginKeys.UAA);
        when(authentication.getPrincipal()).thenReturn("client1");
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
