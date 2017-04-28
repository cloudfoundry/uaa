package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationTestFactory;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.UaaOauth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
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
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientAlreadyExistsException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.util.StringUtils;

import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.oauth.client.ClientConstants.REQUIRED_USER_GROUPS;
import static org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsModification.SECRET;
import static org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder.isUaa;
import static org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService.DEFAULT_DELETE_STATEMENT;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;


public class MultitenantJdbcClientDetailsServiceTests extends JdbcTestBase {
    private MultitenantJdbcClientDetailsService service;

    private static final String SELECT_SQL = "select client_id, client_secret, resource_ids, scope, authorized_grant_types, web_server_redirect_uri, authorities, access_token_validity, refresh_token_validity, lastmodified, required_user_groups from oauth_client_details where client_id=?";

    private static final String INSERT_SQL = "insert into oauth_client_details (client_id, client_secret, resource_ids, scope, authorized_grant_types, web_server_redirect_uri, authorities, access_token_validity, refresh_token_validity, autoapprove, identity_zone_id, lastmodified, required_user_groups) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?)";

    private UaaTestAccounts testAccounts = UaaTestAccounts.standard(null);

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
        otherIdentityZone = new IdentityZone();
        otherIdentityZone.setId("testzone");
        otherIdentityZone.setName("testzone");
        otherIdentityZone.setSubdomain("testzone");

        clientDetails = new BaseClientDetails();
        String clientId = "client-with-id-" + new RandomValueStringGenerator(36).generate();
        clientDetails.setClientId(clientId);

    }

    @Test
    public void event_calls_delete_method() throws Exception {
        ClientDetails client = addClientToDb(generate.generate());
        service.onApplicationEvent(new EntityDeletedEvent<>(client, mock(UaaAuthentication.class)));
        verify(service, times(1)).deleteByClient(eq(client.getClientId()), eq(IdentityZoneHolder.get().getId()));
    }

    @Test
    public void delete_by_client_id() throws Exception {
        //this test ensures that one method calls the other, rather than having its own implementation
        for (IdentityZone zone : Arrays.asList(IdentityZone.getUaa(), otherIdentityZone)) {
            IdentityZoneHolder.set(zone);
            try {
                service.removeClientDetails("some-client-id");
            } catch (Exception e) {
            }
            verify(service, times(1)).deleteByClient(eq("some-client-id"), eq(zone.getId()));
            reset(service);
        }
    }



    @Test
    public void delete_by_client_respects_zone_id_param() throws Exception {
        //this test ensures that one method calls the other, rather than having its own implementation
        for (IdentityZone zone : Arrays.asList(IdentityZone.getUaa(), otherIdentityZone)) {
            reset(service);
            reset(template);
            doReturn(1).when(template).update(anyString(),anyString(),anyString());
            IdentityZoneHolder.set(zone);
            try {
                service.deleteByClient("some-client-id", "zone-id");
            } catch (Exception e) {
            }
            verify(service, times(1)).deleteByClient(eq("some-client-id"), eq("zone-id"));
            verify(template, times(1)).update(DEFAULT_DELETE_STATEMENT, "some-client-id", "zone-id");
        }
    }

    @Test
    public void delete_by_client_id_and_zone() throws Exception {
        List<ClientDetails> defaultZoneClients = new LinkedList<>();
        addClientsInCurrentZone(defaultZoneClients, 5);
        for (IdentityZone zone : Arrays.asList(IdentityZone.getUaa(), otherIdentityZone)) {
            IdentityZoneHolder.set(zone);
            List<ClientDetails> clients = new LinkedList<>();
            addClientsInCurrentZone(clients, 10);
            assertEquals((isUaa() ? 5 : 0) + clients.size(), countClientsInZone(zone.getId()));


            clients.removeIf(
                client -> {
                    assertEquals("We deleted exactly one row", 1, service.deleteByClient(client.getClientId(), zone.getId()));
                    assertEquals("Our client count decreased by 1", (isUaa() ? 5 : 0) + (clients.size()-1), countClientsInZone(zone.getId()));
                    assertFalse("Client "+client.getClientId()+ " was deleted.", clientExists(client.getClientId(), zone.getId()));
                    return true;
                });

            assertEquals(0, clients.size());
            assertEquals(isUaa() ? 5 : 0, countClientsInZone(zone.getId()));
        }
    }

    public void addClientsInCurrentZone(List<ClientDetails> clients, int count) {
        for (int i = 0; i < count; i++) {
            clients.add(addClientToDb(i + "-" + generate.generate()));
        }
    }

    @Test
    public void test_can_delete_zone_clients() throws Exception {
        String id = generate.generate();
        for (IdentityZone zone : Arrays.asList(IdentityZone.getUaa(), otherIdentityZone)) {
            IdentityZoneHolder.set(zone);
            addClientToDb(id);
            assertThat(countClientsInZone(IdentityZoneHolder.get().getId()), is(1));
        }

        service.onApplicationEvent(new EntityDeletedEvent<>(otherIdentityZone, null));
        assertThat(countClientsInZone(otherIdentityZone.getId()), is(0));
    }


    public int countClientsInZone(String zoneId) {
        return jdbcTemplate.queryForObject("select count(*) from oauth_client_details where identity_zone_id=?", new Object[] {zoneId}, Integer.class);
    }

    public boolean clientExists(String clientId, String zoneId) {
        return jdbcTemplate.queryForObject("select count(*) from oauth_client_details where client_id = ? and identity_zone_id=?", new Object[] {clientId, zoneId}, Integer.class) == 1;
    }

    @Test
    public void test_cannot_delete_uaa_zone_clients() throws Exception {
        String id = generate.generate();
        addClientToDb(id);
        String zoneId = IdentityZoneHolder.get().getId();
        assertThat(countClientsInZone(zoneId), is(1));

        service.onApplicationEvent(new EntityDeletedEvent<>(IdentityZoneHolder.get(), null));
        assertThat(countClientsInZone(zoneId), is(1));
    }

    public ClientDetails addClientToDb(String id) {
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId(id);
        clientDetails.setClientSecret("secret");
        service.addClientDetails(clientDetails);
        return service.loadClientByClientId(id);
    }


    @Test(expected = NoSuchClientException.class)
    public void testLoadingClientForNonExistingClientId() {
        service.loadClientByClientId("nonExistingClientId");
    }

    @Test
    public void testLoadingClientIdWithNoDetails() {
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
        assertEquals(null, clientDetails.getAccessTokenValiditySeconds());
        assertEquals(null, clientDetails.getAccessTokenValiditySeconds());
    }

    @Test
    public void testLoadingClientIdWithAdditionalInformation() {

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
    public void autoApproveOnlyReturnedInField_andNotInAdditionalInfo() throws Exception {
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
    public void testLoadingClientIdWithSingleDetails() {
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
    public void load_groups_generates_empty_collection() {
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
            assertEquals(0, ((Collection)userGroups).size());
        }
    }

    @Test
    public void additional_information_does_not_override_user_group_column() throws Exception {
        String[] groups = {"group1", "group2"};
        List<String> requiredGroups = Arrays.asList(groups);
        clientDetails.addAdditionalInformation(REQUIRED_USER_GROUPS, requiredGroups);
        service.addClientDetails(clientDetails);
        assertEquals(1,jdbcTemplate.update("UPDATE oauth_client_details SET additional_information = ? WHERE client_id = ?", JsonUtils.writeValueAsString(clientDetails.getAdditionalInformation()), clientDetails.getClientId()));
        assertEquals(1,jdbcTemplate.update("UPDATE oauth_client_details SET required_user_groups = ? WHERE client_id = ?", "group1,group2,group3", clientDetails.getClientId()));
        ClientDetails updateClient = service.loadClientByClientId(clientDetails.getClientId());
        assertThat((Collection<String>)updateClient.getAdditionalInformation().get(REQUIRED_USER_GROUPS), containsInAnyOrder("group1", "group2", "group3"));
    }

    @Test
    public void create_sets_required_user_groups() {
        String[] groups = {"group1", "group2"};
        List<String> requiredGroups = Arrays.asList(groups);
        clientDetails.addAdditionalInformation(REQUIRED_USER_GROUPS, requiredGroups);
        service.addClientDetails(clientDetails);
        validateRequiredGroups(clientDetails.getClientId(), groups);

        groups = new String[] {"group1", "group2", "group3"};
        requiredGroups = Arrays.asList(groups);
        clientDetails.addAdditionalInformation(REQUIRED_USER_GROUPS, requiredGroups);
        service.updateClientDetails(clientDetails);
        validateRequiredGroups(clientDetails.getClientId(), groups);
    }

    public void validateRequiredGroups(String clientId, String... expectedGroups) {
        String requiredUserGroups = jdbcTemplate.queryForObject("select required_user_groups from oauth_client_details where client_id = ?", String.class, clientId);
        assertNotNull(requiredUserGroups);
        Collection<String> savedGroups = StringUtils.commaDelimitedListToSet(requiredUserGroups);
        assertThat(savedGroups, containsInAnyOrder(expectedGroups));
        String additionalInformation = jdbcTemplate.queryForObject("select additional_information from oauth_client_details where client_id = ?", String.class, clientId);
        for (String s : expectedGroups) {
            assertThat(additionalInformation, not(containsString(s)));
        }
    }


    @Test
    public void testLoadingClientIdWithMultipleDetails() {
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
        assertThat((Collection<String>)requiredUserGroups, containsInAnyOrder("uaa.user","uaa.something"));

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
    public void testAddClientWithNoDetails() {

        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("addedClientIdWithNoDetails");

        service.addClientDetails(clientDetails);

        Map<String, Object> map = jdbcTemplate.queryForMap(SELECT_SQL,
                "addedClientIdWithNoDetails");

        assertEquals("addedClientIdWithNoDetails", map.get("client_id"));
        assertTrue(map.containsKey("client_secret"));
        assertEquals(null, map.get("client_secret"));
    }

    @Test
    public void testAddClientWithSalt() throws Exception {
        String id = "addedClientIdWithSalt";
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId(id);
        clientDetails.setClientSecret("secret");
        clientDetails.addAdditionalInformation(ClientConstants.TOKEN_SALT, "salt");
        service.addClientDetails(clientDetails);
        clientDetails = (BaseClientDetails)service.loadClientByClientId(id);
        assertNotNull(clientDetails);
        assertEquals("salt", clientDetails.getAdditionalInformation().get(ClientConstants.TOKEN_SALT));

        clientDetails.addAdditionalInformation(ClientConstants.TOKEN_SALT, "newsalt");
        service.updateClientDetails(clientDetails);
        clientDetails = (BaseClientDetails)service.loadClientByClientId(id);
        assertNotNull(clientDetails);
        assertEquals("newsalt", clientDetails.getAdditionalInformation().get(ClientConstants.TOKEN_SALT));
    }

    @Test(expected = ClientAlreadyExistsException.class)
    public void testInsertDuplicateClient() {

        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("duplicateClientIdWithNoDetails");

        service.addClientDetails(clientDetails);
        service.addClientDetails(clientDetails);
    }

    @Test
    public void testUpdateClientSecret() {

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
    public void testDeleteClientSecret() {
        String clientId = "client_id_test_delete";
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId(clientId);
        clientDetails.setClientSecret(SECRET);
        service.addClientDetails(clientDetails);
        service.addClientSecret(clientId, "new_secret");

        Map<String, Object> map = jdbcTemplate.queryForMap(SELECT_SQL, clientId);
        String clientSecretBeforeDelete = (String) map.get("client_secret");
        assertNotNull(clientSecretBeforeDelete);
        assertEquals(2, clientSecretBeforeDelete.split(" ").length);
        service.deleteClientSecret(clientId);

        map = jdbcTemplate.queryForMap(SELECT_SQL, clientId);
        String clientSecret = (String) map.get("client_secret");
        assertNotNull(clientSecret);
        assertEquals(1, clientSecret.split(" ").length);
        assertEquals(clientSecretBeforeDelete.split(" ")[1], clientSecret);
    }

    @Test
    public void testDeleteClientSecretForInvalidClient() {
        expectedEx.expect(NoSuchClientException.class);
        expectedEx.expectMessage("No client with requested id: invalid_client_id");
        service.deleteClientSecret("invalid_client_id");
    }

    @Test
    public void testUpdateClientRedirectURI() {

        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("newClientIdWithNoDetails");

        service.addClientDetails(clientDetails);

        String[] redirectURI = { "http://localhost:8080",
                "http://localhost:9090" };
        clientDetails.setRegisteredRedirectUri(new HashSet<String>(Arrays
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
    public void testUpdateNonExistentClient() {

        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("nosuchClientIdWithNoDetails");

        service.updateClientDetails(clientDetails);
    }

    @Test
    public void testRemoveClient() {

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
    public void testRemoveNonExistentClient() {

        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("nosuchClientIdWithNoDetails");

        service.removeClientDetails(clientDetails.getClientId());
    }

    @Test
    public void testFindClients() {

        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("aclient");

        service.addClientDetails(clientDetails);
        int count = service.listClientDetails().size();

        assertEquals(1, count);
    }

    @Test
    public void testLoadingClientInOtherZoneFromOtherZone() {
        IdentityZoneHolder.set(otherIdentityZone);
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("clientInOtherZone");
        service.addClientDetails(clientDetails);
        assertNotNull(service.loadClientByClientId("clientInOtherZone"));
    }

    @Test(expected = NoSuchClientException.class)
    public void testLoadingClientInOtherZoneFromDefaultZoneFails() {
        IdentityZoneHolder.set(otherIdentityZone);
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId("clientInOtherZone");
        service.addClientDetails(clientDetails);
        IdentityZoneHolder.clear();
        service.loadClientByClientId("clientInOtherZone");
    }

    @Test
    public void testAddingClientToOtherIdentityZoneShouldHaveOtherIdentityZoneId() {
        IdentityZoneHolder.set(otherIdentityZone);
        BaseClientDetails clientDetails = new BaseClientDetails();
        String clientId = "clientInOtherZone";
        clientDetails.setClientId(clientId);
        service.addClientDetails(clientDetails);
        String identityZoneId = jdbcTemplate.queryForObject("select identity_zone_id from oauth_client_details where client_id = ?", String.class,clientId);
        assertEquals(otherIdentityZone.getId(), identityZoneId.trim());
    }

    @Test
    public void testAddingClientToDefaultIdentityZoneShouldHaveAnIdentityZoneId() {
        BaseClientDetails clientDetails = new BaseClientDetails();
        String clientId = "clientInDefaultZone";
        clientDetails.setClientId(clientId);
        service.addClientDetails(clientDetails);
        String identityZoneId = jdbcTemplate.queryForObject("select identity_zone_id from oauth_client_details where client_id = ?", String.class,clientId);
        assertEquals(IdentityZone.getUaa().getId(), identityZoneId.trim());
    }

    @Test
    public void testCreatedByIdInCaseOfUser() throws Exception {
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
    public void testCreatedByIdInCaseOfClient() throws Exception {
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
    public void testNullCreatedById() throws Exception {
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

    private Authentication authenticateAsUserAndReturnOldAuth(String userId) {
        Authentication authentication = new OAuth2Authentication(new AuthorizationRequest("client",
            Arrays.asList("read")).createOAuth2Request(), UaaAuthenticationTestFactory.getAuthentication(userId, "joe",
            "joe@test.org"));
        Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();
        SecurityContextHolder.getContext().setAuthentication(authentication);
        return currentAuth;
    }

    private void authenticateAsClient() {
        UaaOauth2Authentication authentication = mock(UaaOauth2Authentication.class);
        when(authentication.getZoneId()).thenReturn(OriginKeys.UAA);
        when(authentication.getPrincipal()).thenReturn("client1");
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
