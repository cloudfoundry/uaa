/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.client.InvalidClientDetailsException;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsModification;
import org.cloudfoundry.identity.uaa.oauth.client.SecretChangeRequest;
import org.cloudfoundry.identity.uaa.resources.SearchResults;
import org.cloudfoundry.identity.uaa.test.TestAccountSetup;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.zone.ClientSecretPolicy;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertFalse;
import static junit.framework.Assert.assertTrue;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.doesSupportZoneDNS;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;


/**
 * @author Dave Syer
 * @author Luke Taylor
 */
public class ClientAdminEndpointsIntegrationTests {

    public static final String SECRET_TOO_LONG = "adfdfdasgdasgasdgafsgasfgfasgfadsgfagsagasddsafdsafsdfdafsdafdsfasdffasfasdfasdfdsfds" +
        "ewrewrewqrweqrewqrewqrewerwqqweewqrdsadsfewqrewqrtewrewrewrewrererererererererererdfadsafasfdasfsdaf" +
        "dsfasdfdsagfdsao43o4p43adfsfasdvcdasfmdsafzxcvaddsaaddfsafdsafdsfdsdfsfdsfdsasdfadfsadfsasadfsdfadfs";
    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    private UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @Rule
    public TestAccountSetup testAccountSetup = TestAccountSetup.standard(serverRunning, testAccounts);

    private OAuth2AccessToken token;
    private HttpHeaders headers;
    private List<ClientDetailsModification> clientDetailsModifications;

    @Before
    public void setUp() throws Exception {
        token = getClientCredentialsAccessToken("clients.read,clients.write,clients.admin");
        headers = getAuthenticatedHeaders(token);
    }

    @Test
    public void testGetClient() throws Exception {
        HttpHeaders headers = getAuthenticatedHeaders(getClientCredentialsAccessToken("clients.read"));
        ResponseEntity<String> result = serverRunning.getForString("/oauth/clients/cf", headers);
        assertEquals(HttpStatus.OK, result.getStatusCode());
        assertTrue(result.getBody().contains("cf"));
    }

    @Test
    public void testListClients() throws Exception {
        HttpHeaders headers = getAuthenticatedHeaders(getClientCredentialsAccessToken("clients.read"));
        ResponseEntity<String> result = serverRunning.getForString("/oauth/clients", headers);
        assertEquals(HttpStatus.OK, result.getStatusCode());
        // System.err.println(result.getBody());
        assertTrue(result.getBody().contains("\"client_id\":\"cf\""));
        assertFalse(result.getBody().contains("secret\":"));
    }

    @Before
    public void setupClients() {
        clientDetailsModifications = new ArrayList<>();
    }

    @After
    public void teardownClients() {
        for (ClientDetailsModification clientDetailsModification : clientDetailsModifications) {
            serverRunning.getRestTemplate()
                .exchange(serverRunning.getUrl("/oauth/clients/{client}"), HttpMethod.DELETE,
                    new HttpEntity<BaseClientDetails>(clientDetailsModification, headers), Void.class,
                    clientDetailsModification.getClientId());
        }
    }

    @Test
    public void testListClientsWithExtremePagination_defaultsTo500() throws Exception {
        for (int i = 0; i < 502; i++) {
            clientDetailsModifications.add(createClient("client_credentials"));
        }

        HttpHeaders headers = getAuthenticatedHeaders(getClientCredentialsAccessToken("clients.read"));
        ResponseEntity<String> result = serverRunning.getForString("/oauth/clients?count=3000", headers);
        assertEquals(HttpStatus.OK, result.getStatusCode());

        SearchResults searchResults = new ObjectMapper().readValue(result.getBody(), SearchResults.class);
        assertThat(searchResults.getItemsPerPage(), is(500));
        assertThat((List<?>) searchResults.getResources(), hasSize(500));
        assertThat(searchResults.getTotalResults(), greaterThan(500));
    }

    @Test
    public void testCreateClient() throws Exception {
        createClient("client_credentials");
    }

    @Test
    public void testCreateClients() throws Exception {
        doCreateClients();
    }

    public ClientDetailsModification[] doCreateClients() throws Exception {
        headers = getAuthenticatedHeaders(getClientCredentialsAccessToken("clients.admin,clients.read,clients.write,clients.secret"));
        headers.add("Accept", "application/json");
        RandomValueStringGenerator gen = new RandomValueStringGenerator();
        String[] ids = new String[5];
        ClientDetailsModification[] clients = new ClientDetailsModification[ids.length];
        for (int i = 0; i < ids.length; i++) {
            ids[i] = gen.generate();
            ClientDetailsModification detailsModification = new ClientDetailsModification();
            detailsModification.setClientId(ids[i]);
            detailsModification.setScope(Arrays.asList("foo", "bar"));
            detailsModification.setAuthorizedGrantTypes(Collections.singletonList("client_credentials"));
            detailsModification.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("uaa.none"));
            clients[i] = detailsModification;
            clients[i].setClientSecret("secret");
            clients[i].setAdditionalInformation(Collections.<String, Object>singletonMap("foo",
                    Collections.singletonList("bar")));
            clients[i].setRegisteredRedirectUri(Collections.singleton("http://redirect.url"));
        }
        ResponseEntity<ClientDetailsModification[]> result =
            serverRunning.getRestTemplate().exchange(
                serverRunning.getUrl("/oauth/clients/tx"),
                HttpMethod.POST,
                new HttpEntity<ClientDetailsModification[]>(clients, headers),
                ClientDetailsModification[].class);
        assertEquals(HttpStatus.CREATED, result.getStatusCode());
        validateClients(clients, result.getBody());
        for (String id : ids) {
            ClientDetails client = getClient(id);
            assertNotNull(client);
        }
        return result.getBody();
    }

    @Test
    public void createClientWithCommaDelimitedScopesValidatesAllTheScopes() throws Exception {
        // log in as admin
        OAuth2AccessToken adminToken = getClientCredentialsAccessToken("");
        HttpHeaders adminHeaders = getAuthenticatedHeaders(adminToken);

        // make client that can create other clients
        String newClientId = new RandomValueStringGenerator().generate();
        BaseClientDetails clientCreator = new BaseClientDetails(
                newClientId,
                "",
                "clients.write,uaa.user",
                "client_credentials",
                "clients.write,uaa.user"
        );
        clientCreator.setClientSecret("secret");
        ResponseEntity<UaaException> result = serverRunning.getRestTemplate().exchange(
            serverRunning.getUrl("/oauth/clients"), HttpMethod.POST,
            new HttpEntity<>(clientCreator, adminHeaders), UaaException.class);

        // ensure success
        assertEquals(HttpStatus.CREATED, result.getStatusCode());

        // log in as new client
        OAuth2AccessToken token = getClientCredentialsAccessToken(clientCreator.getClientId(), clientCreator.getClientSecret(), "");
        HttpHeaders headers = getAuthenticatedHeaders(token);

        // make client with restricted scopes
        BaseClientDetails invalidClient = new BaseClientDetails(
                new RandomValueStringGenerator().generate(),
                "",
                newClientId + ".admin,uaa.admin",
                "client_credentials",
                "uaa.none"
        );
        invalidClient.setClientSecret("secret");
        ResponseEntity<UaaException> invalidClientRequest = serverRunning.getRestTemplate().exchange(
                serverRunning.getUrl("/oauth/clients"), HttpMethod.POST,
                new HttpEntity<>(invalidClient, headers), UaaException.class);

        // ensure correct failure
        assertEquals(HttpStatus.BAD_REQUEST, invalidClientRequest.getStatusCode());
        assertEquals("invalid_client", invalidClientRequest.getBody().getErrorCode());
        assertTrue("Error message is unexpected", invalidClientRequest.getBody().getMessage().startsWith("uaa.admin is not an allowed scope for caller"));
    }

    @Test
    public void createClientWithoutSecretIsRejected() throws Exception {
        OAuth2AccessToken token = getClientCredentialsAccessToken("clients.read,clients.write");
        HttpHeaders headers = getAuthenticatedHeaders(token);
        BaseClientDetails invalidSecretClient = new BaseClientDetails(new RandomValueStringGenerator().generate(), "", "foo,bar",
            "client_credentials", "uaa.none");
        invalidSecretClient.setClientSecret("tooLongSecret");
        ResponseEntity<UaaException> result = serverRunning.getRestTemplate().exchange(
            serverRunning.getUrl("/oauth/clients"), HttpMethod.POST,
            new HttpEntity<BaseClientDetails>(invalidSecretClient, headers), UaaException.class);
        assertEquals(HttpStatus.BAD_REQUEST, result.getStatusCode());
        assertEquals("invalid_client", result.getBody().getErrorCode());
    }


    @Test
    public void createClientWithTooLongSecretIsRejected() throws Exception {
        OAuth2AccessToken token = getClientCredentialsAccessToken("clients.read,clients.write");
        HttpHeaders headers = getAuthenticatedHeaders(token);
        BaseClientDetails client = new BaseClientDetails(new RandomValueStringGenerator().generate(), "", "foo,bar",
            "client_credentials", "uaa.none");
        client.setClientSecret(SECRET_TOO_LONG);
        ResponseEntity<UaaException> result = serverRunning.getRestTemplate().exchange(
            serverRunning.getUrl("/oauth/clients"), HttpMethod.POST,
            new HttpEntity<BaseClientDetails>(client, headers), UaaException.class);
        assertEquals(HttpStatus.BAD_REQUEST, result.getStatusCode());
        assertEquals("invalid_client", result.getBody().getErrorCode());
    }

    @Test
    public void createClientWithStrictSecretPolicyTest() throws Exception {
        assertTrue("Expected testzone1.localhost and testzone2.localhost to resolve to 127.0.0.1", doesSupportZoneDNS());
        String testZoneId = "testzone1";

        RestTemplate adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(serverRunning.getBaseUrl(), new String[0], "admin", "adminsecret"));
        RestTemplate identityClient = IntegrationTestUtils
            .getClientCredentialsTemplate(IntegrationTestUtils.getClientCredentialsResource(serverRunning.getBaseUrl(),
                new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret"));

        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        //min length 5, max length 12, requires 1 uppercase lowercase digit and specialChar, expries 6 months.
        config.setClientSecretPolicy(new ClientSecretPolicy(5, 12, 1, 1, 1, 1, 6));
        IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, serverRunning.getBaseUrl(), testZoneId, testZoneId, config);


        BaseClientDetails client = new BaseClientDetails(new RandomValueStringGenerator().generate(), "", "foo,bar",
            "client_credentials", "uaa.none");
        client.setClientSecret("Secret1@");

        String zoneAdminToken = IntegrationTestUtils.getZoneAdminToken(serverRunning.getBaseUrl(), serverRunning, testZoneId);
        HttpHeaders xZoneHeaders = getAuthenticatedHeaders(zoneAdminToken);
        xZoneHeaders.add(IdentityZoneSwitchingFilter.HEADER, testZoneId);
        ResponseEntity<UaaException> result = serverRunning.getRestTemplate().exchange(
            serverRunning.getBaseUrl() + "/oauth/clients", HttpMethod.POST,
            new HttpEntity<BaseClientDetails>(client, xZoneHeaders), UaaException.class);

        Assert.assertEquals(HttpStatus.CREATED, result.getStatusCode());

        //Negative Test
        BaseClientDetails failClient = new BaseClientDetails(new RandomValueStringGenerator().generate(), "", "foo,bar",
            "client_credentials", "uaa.none");
        failClient.setClientSecret("badsecret");
        result = serverRunning.getRestTemplate().exchange(
            serverRunning.getBaseUrl() + "/oauth/clients", HttpMethod.POST,
            new HttpEntity<BaseClientDetails>(failClient, xZoneHeaders), UaaException.class);

        assertEquals(HttpStatus.BAD_REQUEST, result.getStatusCode());

        //cleanup
        config.setClientSecretPolicy(new ClientSecretPolicy(0, 255, 0, 0, 0, 0, 6));
        IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, serverRunning.getBaseUrl(), testZoneId, testZoneId, config);
    }

    @Test
    public void testClientSecretExpiryCannotBeSet() {
        assertTrue("Expected testzone1.localhost and testzone2.localhost to resolve to 127.0.0.1", doesSupportZoneDNS());
        String testZoneId = "testzone1";

        RestTemplate adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(serverRunning.getBaseUrl(), new String[0], "admin", "adminsecret"));
        RestTemplate identityClient = IntegrationTestUtils
            .getClientCredentialsTemplate(IntegrationTestUtils.getClientCredentialsResource(serverRunning.getBaseUrl(),
                new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret"));

        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        //min length 5, max length 12, requires 1 uppercase lowercase digit and specialChar, expries 6 months.
        config.setClientSecretPolicy(new ClientSecretPolicy(5, 12, 1, 1, 1, 1, 6));
        IdentityZone createdZone = IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, serverRunning.getBaseUrl(), testZoneId, testZoneId, config);
        assertEquals(-1, createdZone.getConfig().getClientSecretPolicy().getExpireSecretInMonths());
        config.setClientSecretPolicy(new ClientSecretPolicy(0, 255, 0, 0, 0, 0, 6));
        IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, serverRunning.getBaseUrl(), testZoneId, testZoneId, config);
    }

    @Test
    public void nonImplicitGrantClientWithoutSecretIsRejectedTxFails() throws Exception {
        headers = getAuthenticatedHeaders(getClientCredentialsAccessToken("clients.admin,clients.read,clients.write,clients.secret"));
        headers.add("Accept", "application/json");
        String grantTypes = "client_credentials";
        RandomValueStringGenerator gen = new RandomValueStringGenerator();
        String[] ids = new String[5];
        BaseClientDetails[] clients = new BaseClientDetails[ids.length];
        for (int i = 0; i < ids.length; i++) {
            ids[i] = gen.generate();
            clients[i] = new BaseClientDetails(ids[i], "", "foo,bar", grantTypes, "uaa.none");
            clients[i].setClientSecret("secret");
            clients[i].setAdditionalInformation(Collections.<String, Object>singletonMap("foo",
                    Collections.singletonList("bar")));
        }
        clients[clients.length - 1].setClientSecret(null);
        ResponseEntity<UaaException> result =
            serverRunning.getRestTemplate().exchange(
                serverRunning.getUrl("/oauth/clients/tx"),
                HttpMethod.POST,
                new HttpEntity<BaseClientDetails[]>(clients, headers),
                UaaException.class);
        assertEquals(HttpStatus.BAD_REQUEST, result.getStatusCode());
        for (String id : ids) {
            ClientDetails client = getClient(id);
            assertNull(client);
        }
    }

    @Test
    public void duplicateIdsIsRejectedTxFails() throws Exception {
        headers = getAuthenticatedHeaders(getClientCredentialsAccessToken("clients.admin,clients.read,clients.write,clients.secret"));
        headers.add("Accept", "application/json");
        String grantTypes = "client_credentials";
        RandomValueStringGenerator gen = new RandomValueStringGenerator();
        String[] ids = new String[5];
        BaseClientDetails[] clients = new BaseClientDetails[ids.length];
        for (int i = 0; i < ids.length; i++) {
            ids[i] = gen.generate();
            clients[i] = new BaseClientDetails(ids[i], "", "foo,bar", grantTypes, "uaa.none");
            clients[i].setClientSecret("secret");
            clients[i].setAdditionalInformation(Collections.<String, Object>singletonMap("foo",
                    Collections.singletonList("bar")));
            clients[i].setRegisteredRedirectUri(Collections.singleton("http://redirect.url"));
        }
        clients[clients.length - 1].setClientId(ids[0]);
        ResponseEntity<UaaException> result =
            serverRunning.getRestTemplate().exchange(
                serverRunning.getUrl("/oauth/clients/tx"),
                HttpMethod.POST,
                new HttpEntity<BaseClientDetails[]>(clients, headers),
                UaaException.class);
        assertEquals(HttpStatus.CONFLICT, result.getStatusCode());
        for (String id : ids) {
            ClientDetails client = getClient(id);
            assertNull(client);
        }
    }

    @Test
    public void implicitAndAuthCodeGrantClient() {
        BaseClientDetails client = new BaseClientDetails(new RandomValueStringGenerator().generate(), "", "foo,bar",
            "implicit,authorization_code", "uaa.none");
        ResponseEntity<UaaException> result = serverRunning.getRestTemplate().exchange(
            serverRunning.getUrl("/oauth/clients"), HttpMethod.POST,
            new HttpEntity<BaseClientDetails>(client, headers), UaaException.class);
        assertEquals(HttpStatus.BAD_REQUEST, result.getStatusCode());
        assertEquals("invalid_client", result.getBody().getErrorCode());
    }

    @Test
    public void implicitGrantClientWithoutSecretIsOk() {
        BaseClientDetails client = new BaseClientDetails(new RandomValueStringGenerator().generate(), "", "foo,bar",
            "implicit", "uaa.none", "http://redirect.url");
        ResponseEntity<Void> result = serverRunning.getRestTemplate().exchange(serverRunning.getUrl("/oauth/clients"),
            HttpMethod.POST, new HttpEntity<BaseClientDetails>(client, headers), Void.class);

        assertEquals(HttpStatus.CREATED, result.getStatusCode());
    }

    @Test
    public void passwordGrantClientWithoutSecretIsOk() {
        BaseClientDetails client = new BaseClientDetails(new RandomValueStringGenerator().generate(), "", "foo,bar",
            "password", "uaa.none", "http://redirect.url");
        ResponseEntity<Void> result = serverRunning.getRestTemplate().exchange(serverRunning.getUrl("/oauth/clients"),
            HttpMethod.POST, new HttpEntity<BaseClientDetails>(client, headers), Void.class);

        assertEquals(HttpStatus.CREATED, result.getStatusCode());
    }

    @Test
    public void authzCodeGrantAutomaticallyAddsRefreshToken() throws Exception {
        BaseClientDetails client = createClient(GRANT_TYPE_AUTHORIZATION_CODE);

        ResponseEntity<String> result = serverRunning.getForString("/oauth/clients/" + client.getClientId(), headers);
        assertEquals(HttpStatus.OK, result.getStatusCode());
        assertTrue(result.getBody().contains("\"authorized_grant_types\":[\"authorization_code\",\"refresh_token\"]"));
    }

    @Test
    public void passwordGrantAutomaticallyAddsRefreshToken() throws Exception {
        BaseClientDetails client = createClient("password");

        ResponseEntity<String> result = serverRunning.getForString("/oauth/clients/" + client.getClientId(), headers);
        assertEquals(HttpStatus.OK, result.getStatusCode());
        assertTrue(result.getBody().contains("\"authorized_grant_types\":[\"password\",\"refresh_token\"]"));
    }

    @Test
    public void testUpdateClient() throws Exception {
        BaseClientDetails client = createClient("client_credentials");

        client.setResourceIds(Collections.singleton("foo"));
        client.setClientSecret(null);
        client.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("some.crap"));
        client.setAccessTokenValiditySeconds(60);
        client.setRefreshTokenValiditySeconds(120);
        client.setAdditionalInformation(Collections.<String, Object>singletonMap("foo",
                Collections.singletonList("rab")));

        ResponseEntity<Void> result = serverRunning.getRestTemplate().exchange(
            serverRunning.getUrl("/oauth/clients/{client}"),
            HttpMethod.PUT, new HttpEntity<BaseClientDetails>(client, headers), Void.class,
            client.getClientId());
        assertEquals(HttpStatus.OK, result.getStatusCode());

        ResponseEntity<String> response = serverRunning.getForString("/oauth/clients/" + client.getClientId(), headers);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        String body = response.getBody();
        assertTrue(body.contains(client.getClientId()));
        assertTrue(body.contains("some.crap"));
        assertTrue(body.contains("refresh_token_validity\":120"));
        assertTrue(body.contains("access_token_validity\":60"));
        assertTrue("Wrong body: " + body, body.contains("\"foo\":[\"rab\"]"));

    }

    @Test
    public void testUpdateClients() throws Exception {
        BaseClientDetails[] clients = doCreateClients();
        headers = getAuthenticatedHeaders(getClientCredentialsAccessToken("clients.admin,clients.read,clients.write,clients.secret"));
        headers.add("Accept", "application/json");
        for (BaseClientDetails c : clients) {
            c.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("some.crap"));
            c.setAccessTokenValiditySeconds(60);
            c.setRefreshTokenValiditySeconds(120);
        }
        ResponseEntity<BaseClientDetails[]> result =
            serverRunning.getRestTemplate().exchange(
                serverRunning.getUrl("/oauth/clients/tx"),
                HttpMethod.PUT,
                new HttpEntity<BaseClientDetails[]>(clients, headers),
                BaseClientDetails[].class);
        assertEquals(HttpStatus.OK, result.getStatusCode());
        validateClients(clients, result.getBody());
        for (BaseClientDetails c : clients) {
            ClientDetails client = getClient(c.getClientId());
            assertNotNull(client);
            assertEquals((Integer) 120, client.getRefreshTokenValiditySeconds());
            assertEquals((Integer) 60, client.getAccessTokenValiditySeconds());
        }
    }

    @Test
    public void testDeleteClients() throws Exception {
        BaseClientDetails[] clients = doCreateClients();
        headers = getAuthenticatedHeaders(getClientCredentialsAccessToken("clients.admin,clients.read,clients.write,clients.secret,clients.admin"));
        headers.add("Accept", "application/json");
        ResponseEntity<BaseClientDetails[]> result =
            serverRunning.getRestTemplate().exchange(
                serverRunning.getUrl("/oauth/clients/tx/delete"),
                HttpMethod.POST,
                    new HttpEntity<>(clients, headers),
                BaseClientDetails[].class);
        assertEquals(HttpStatus.OK, result.getStatusCode());
        validateClients(clients, result.getBody());
        for (BaseClientDetails c : clients) {
            ClientDetails client = getClient(c.getClientId());
            assertNull(client);
        }
    }

    @Test
    public void testDeleteClientsMissingId() throws Exception {
        BaseClientDetails[] clients = doCreateClients();
        headers = getAuthenticatedHeaders(getClientCredentialsAccessToken("clients.admin,clients.read,clients.write,clients.secret,clients.admin"));
        headers.add("Accept", "application/json");
        String oldId = clients[clients.length - 1].getClientId();
        clients[clients.length - 1].setClientId("unknown.id");
        ResponseEntity<BaseClientDetails[]> result =
            serverRunning.getRestTemplate().exchange(
                serverRunning.getUrl("/oauth/clients/tx/delete"),
                HttpMethod.POST,
                new HttpEntity<BaseClientDetails[]>(clients, headers),
                BaseClientDetails[].class);
        assertEquals(HttpStatus.NOT_FOUND, result.getStatusCode());
        clients[clients.length - 1].setClientId(oldId);
        for (BaseClientDetails c : clients) {
            ClientDetails client = getClient(c.getClientId());
            assertNotNull(client);
        }
    }

    @Test
    public void testChangeSecret() throws Exception {
        headers = getAuthenticatedHeaders(getClientCredentialsAccessToken("clients.read,clients.write,clients.secret,uaa.admin"));
        BaseClientDetails client = createClient("client_credentials");

        client.setResourceIds(Collections.singleton("foo"));

        SecretChangeRequest change = new SecretChangeRequest();
        change.setOldSecret(client.getClientSecret());
        change.setSecret("newsecret");
        ResponseEntity<Void> result = serverRunning.getRestTemplate().exchange(
            serverRunning.getUrl("/oauth/clients/{client}/secret"),
            HttpMethod.PUT, new HttpEntity<SecretChangeRequest>(change, headers), Void.class,
            client.getClientId());
        assertEquals(HttpStatus.OK, result.getStatusCode());
    }


    @Test
    public void testCreateClientsWithStrictSecretPolicy() throws Exception {
        headers = getAuthenticatedHeaders(getClientCredentialsAccessToken("clients.read,clients.write,clients.secret,uaa.admin"));
        BaseClientDetails client = createClient("client_credentials");

        client.setResourceIds(Collections.singleton("foo"));

        SecretChangeRequest change = new SecretChangeRequest();
        change.setOldSecret(client.getClientSecret());
        change.setSecret(SECRET_TOO_LONG);
        ResponseEntity<Void> result = serverRunning.getRestTemplate().exchange(
            serverRunning.getUrl("/oauth/clients/{client}/secret"),
            HttpMethod.PUT, new HttpEntity<SecretChangeRequest>(change, headers), Void.class,
            client.getClientId());
        assertEquals(HttpStatus.BAD_REQUEST, result.getStatusCode());
    }

    @Test
    public void testDeleteClient() throws Exception {
        BaseClientDetails client = createClient("client_credentials");

        client.setResourceIds(Collections.singleton("foo"));

        ResponseEntity<Void> result = serverRunning.getRestTemplate()
            .exchange(serverRunning.getUrl("/oauth/clients/{client}"), HttpMethod.DELETE,
                new HttpEntity<BaseClientDetails>(client, headers), Void.class,
                client.getClientId());
        assertEquals(HttpStatus.OK, result.getStatusCode());
    }

    @Test
    public void testAddUpdateAndDeleteTx() throws Exception {
        ClientDetailsModification[] clients = doCreateClients();
        for (int i = 1; i < clients.length; i++) {
            clients[i] = new ClientDetailsModification(clients[i]);
            clients[i].setRefreshTokenValiditySeconds(120);
            clients[i].setAction(ClientDetailsModification.UPDATE);
            clients[i].setClientSecret("secret");
        }
        clients[0].setClientId(new RandomValueStringGenerator().generate());
        clients[0].setRefreshTokenValiditySeconds(60);
        clients[0].setAction(ClientDetailsModification.ADD);
        clients[0].setClientSecret("secret");

        clients[0].setClientId(new RandomValueStringGenerator().generate());
        clients[clients.length - 1].setAction(ClientDetailsModification.DELETE);


        headers = getAuthenticatedHeaders(getClientCredentialsAccessToken("clients.admin"));
        headers.add("Accept", "application/json");
        String oldId = clients[clients.length - 1].getClientId();
        ResponseEntity<BaseClientDetails[]> result =
            serverRunning.getRestTemplate().exchange(
                serverRunning.getUrl("/oauth/clients/tx/modify"),
                HttpMethod.POST,
                new HttpEntity<ClientDetailsModification[]>(clients, headers),
                BaseClientDetails[].class);
        assertEquals(HttpStatus.OK, result.getStatusCode());
        //set the deleted client ID so we can verify it is gone.
        clients[clients.length - 1].setClientId(oldId);
        for (int i = 0; i < clients.length; i++) {
            ClientDetails client = getClient(clients[i].getClientId());
            if (i == (clients.length - 1)) {
                assertNull(client);
            } else {
                assertNotNull(client);
            }
        }
    }

    @Test
    // CFID-372
    public void testCreateExistingClientFails() throws Exception {
        BaseClientDetails client = createClient("client_credentials");

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> attempt = serverRunning.getRestTemplate().exchange(serverRunning.getUrl("/oauth/clients"),
            HttpMethod.POST, new HttpEntity<BaseClientDetails>(client, headers), Map.class);
        assertEquals(HttpStatus.CONFLICT, attempt.getStatusCode());
        @SuppressWarnings("unchecked")
        Map<String, String> map = attempt.getBody();
        assertEquals("invalid_client", map.get("error"));
    }

    @Test
    public void testClientApprovalsDeleted() throws Exception {
        //create client
        BaseClientDetails client = createClient("client_credentials", "password");
        assertNotNull(getClient(client.getClientId()));
        //issue a user token for this client
        OAuth2AccessToken userToken = getUserAccessToken(client.getClientId(), "secret", testAccounts.getUserName(), testAccounts.getPassword(), "oauth.approvals");
        //make sure we don't have any approvals
        Approval[] approvals = getApprovals(userToken.getValue(), client.getClientId());
        Assert.assertEquals(0, approvals.length);
        //create three approvals
        addApprovals(userToken.getValue(), client.getClientId());
        approvals = getApprovals(userToken.getValue(), client.getClientId());
        Assert.assertEquals(3, approvals.length);
        //delete the client
        ResponseEntity<Void> result = serverRunning.getRestTemplate().exchange(serverRunning.getUrl("/oauth/clients/{client}"), HttpMethod.DELETE,
            new HttpEntity<BaseClientDetails>(client, getAuthenticatedHeaders(token)), Void.class, client.getClientId());
        assertEquals(HttpStatus.OK, result.getStatusCode());

        //create a client that can read another clients approvals
        String deletedClientId = client.getClientId();
        client = createApprovalsClient("password");
        userToken = getUserAccessToken(client.getClientId(), "secret", testAccounts.getUserName(), testAccounts.getPassword(), "oauth.approvals");
        //make sure we don't have any approvals
        approvals = getApprovals(userToken.getValue(), deletedClientId);
        Assert.assertEquals(0, approvals.length);
        assertNull(getClient(deletedClientId));
    }

    @Test
    public void testClientTxApprovalsDeleted() throws Exception {
        //create client
        BaseClientDetails client = createClient("client_credentials", "password");
        assertNotNull(getClient(client.getClientId()));
        //issue a user token for this client
        OAuth2AccessToken userToken = getUserAccessToken(client.getClientId(), "secret", testAccounts.getUserName(), testAccounts.getPassword(), "oauth.approvals");
        //make sure we don't have any approvals
        Approval[] approvals = getApprovals(userToken.getValue(), client.getClientId());
        Assert.assertEquals(0, approvals.length);
        //create three approvals
        addApprovals(userToken.getValue(), client.getClientId());
        approvals = getApprovals(userToken.getValue(), client.getClientId());
        Assert.assertEquals(3, approvals.length);
        //delete the client
        ResponseEntity<Void> result = serverRunning.getRestTemplate().exchange(serverRunning.getUrl("/oauth/clients/tx/delete"), HttpMethod.POST,
            new HttpEntity<BaseClientDetails[]>(new BaseClientDetails[]{client}, getAuthenticatedHeaders(getClientCredentialsAccessToken("clients.admin"))), Void.class);
        assertEquals(HttpStatus.OK, result.getStatusCode());
        //create a client that can read another clients approvals
        String deletedClientId = client.getClientId();
        client = createApprovalsClient("password");
        userToken = getUserAccessToken(client.getClientId(), "secret", testAccounts.getUserName(), testAccounts.getPassword(), "oauth.approvals");
        //make sure we don't have any approvals
        approvals = getApprovals(userToken.getValue(), deletedClientId);
        Assert.assertEquals(0, approvals.length);
        assertNull(getClient(deletedClientId));
    }

    @Test
    public void testClientTxModifyApprovalsDeleted() throws Exception {
        //create client
        ClientDetailsModification client = createClient("client_credentials", "password");
        assertNotNull(getClient(client.getClientId()));
        //issue a user token for this client
        OAuth2AccessToken userToken = getUserAccessToken(client.getClientId(), "secret", testAccounts.getUserName(), testAccounts.getPassword(), "oauth.approvals");
        //make sure we don't have any approvals
        Approval[] approvals = getApprovals(userToken.getValue(), client.getClientId());
        Assert.assertEquals(0, approvals.length);
        //create three approvals
        addApprovals(userToken.getValue(), client.getClientId());
        approvals = getApprovals(userToken.getValue(), client.getClientId());
        Assert.assertEquals(3, approvals.length);
        //delete the client
        client.setAction(ClientDetailsModification.DELETE);
        ResponseEntity<Void> result = serverRunning.getRestTemplate().exchange(serverRunning.getUrl("/oauth/clients/tx/modify"), HttpMethod.POST,
            new HttpEntity<BaseClientDetails[]>(new BaseClientDetails[]{client}, getAuthenticatedHeaders(getClientCredentialsAccessToken("clients.admin"))), Void.class);
        assertEquals(HttpStatus.OK, result.getStatusCode());
        //create a client that can read another clients approvals
        String deletedClientId = client.getClientId();
        client = createApprovalsClient("password");
        userToken = getUserAccessToken(client.getClientId(), "secret", testAccounts.getUserName(), testAccounts.getPassword(), "oauth.approvals");
        //make sure we don't have any approvals
        approvals = getApprovals(userToken.getValue(), deletedClientId);
        Assert.assertEquals(0, approvals.length);
        assertNull(getClient(deletedClientId));
    }

    private Approval[] getApprovals(String token, String clientId) {
        String filter = "client_id eq \"" + clientId + "\"";
        HttpHeaders headers = getAuthenticatedHeaders(token);

        ResponseEntity<Approval[]> approvals =
            serverRunning.getRestTemplate().exchange(serverRunning.getUrl("/approvals"),
                HttpMethod.GET,
                new HttpEntity<>(headers),
                Approval[].class,
                filter);
        assertEquals(HttpStatus.OK, approvals.getStatusCode());
        return Arrays.stream(approvals.getBody()).filter(a -> clientId.equals(a.getClientId())).toArray(Approval[]::new);
    }


    private Approval[] addApprovals(String token, String clientId) {
        Date oneMinuteAgo = new Date(System.currentTimeMillis() - 60000);
        Date expiresAt = new Date(System.currentTimeMillis() + 60000);
        Approval[] approvals = new Approval[]{
            new Approval()
                .setUserId(null)
                .setClientId(clientId)
                .setScope("cloud_controller.read")
                .setExpiresAt(expiresAt)
                .setStatus(Approval.ApprovalStatus.APPROVED)
                .setLastUpdatedAt(oneMinuteAgo),
            new Approval()
                .setUserId(null)
                .setClientId(clientId)
                .setScope("openid")
                .setExpiresAt(expiresAt)
                .setStatus(Approval.ApprovalStatus.APPROVED)
                .setLastUpdatedAt(oneMinuteAgo),
            new Approval()
                .setUserId(null)
                .setClientId(clientId)
                .setScope("password.write")
                .setExpiresAt(expiresAt)
                .setStatus(Approval.ApprovalStatus.APPROVED)
                .setLastUpdatedAt(oneMinuteAgo)
        };

        HttpHeaders headers = getAuthenticatedHeaders(token);
        HttpEntity<Approval[]> entity = new HttpEntity<Approval[]>(approvals, headers);
        ResponseEntity<Approval[]> response = serverRunning.getRestTemplate().exchange(
            serverRunning.getUrl("/approvals/{clientId}"),
            HttpMethod.PUT,
            entity,
            Approval[].class,
            clientId);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        return response.getBody();
    }

    private ClientDetailsModification createClient(String... grantTypes) {
        return createClientWithSecret("secret", grantTypes);
    }

    private ClientDetailsModification createClientWithSecret(String secret, String... grantTypes) {
        ClientDetailsModification client = new ClientDetailsModification();
        client.setClientId(new RandomValueStringGenerator().generate());
        client.setScope(Arrays.asList("oauth.approvals", "foo", "bar"));
        client.setAuthorizedGrantTypes(Arrays.asList(grantTypes));
        client.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("uaa.none"));
        client.setClientSecret(secret);
        client.setAdditionalInformation(Collections.<String, Object>singletonMap("foo",
                Collections.singletonList("bar")));
        client.setRegisteredRedirectUri(Collections.singleton("http://redirect.url"));
        ResponseEntity<Void> result = serverRunning.getRestTemplate().exchange(serverRunning.getUrl("/oauth/clients"),
            HttpMethod.POST, new HttpEntity<BaseClientDetails>(client, headers), Void.class);
        assertEquals(HttpStatus.CREATED, result.getStatusCode());
        return client;
    }

    private ClientDetailsModification createApprovalsClient(String... grantTypes) {
        ClientDetailsModification detailsModification = new ClientDetailsModification();
        detailsModification.setClientId(new RandomValueStringGenerator().generate());
        detailsModification.setScope(Arrays.asList("oauth.login", "oauth.approvals", "foo", "bar"));
        detailsModification.setAuthorizedGrantTypes(Arrays.asList(grantTypes));
        detailsModification.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("uaa.none"));
        detailsModification.setClientSecret("secret");
        detailsModification.setAdditionalInformation(Collections.<String, Object>singletonMap("foo",
                Collections.singletonList("bar")));
        detailsModification.setRegisteredRedirectUri(Collections.singleton("http://redirect.url"));
        ResponseEntity<Void> result = serverRunning.getRestTemplate().exchange(serverRunning.getUrl("/oauth/clients"),
            HttpMethod.POST, new HttpEntity<BaseClientDetails>(detailsModification, headers), Void.class);
        assertEquals(HttpStatus.CREATED, result.getStatusCode());
        return detailsModification;
    }

    public HttpHeaders getAuthenticatedHeaders(OAuth2AccessToken token) {
        return getAuthenticatedHeaders(token.getValue());
    }

    public HttpHeaders getAuthenticatedHeaders(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", "Bearer " + token);
        return headers;
    }

    private OAuth2AccessToken getClientCredentialsAccessToken(String scope) {
        String clientId = testAccounts.getAdminClientId();
        String clientSecret = testAccounts.getAdminClientSecret();

        return getClientCredentialsAccessToken(clientId, clientSecret, scope);
    }

    private OAuth2AccessToken getClientCredentialsAccessToken(String clientId, String clientSecret, String scope) {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add("grant_type", "client_credentials");
        formData.add("client_id", clientId);
        formData.add("scope", scope);
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        headers.set("Authorization",
            "Basic " + new String(Base64.encode(String.format("%s:%s", clientId, clientSecret).getBytes())));

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap("/oauth/token", formData, headers);
        assertEquals(HttpStatus.OK, response.getStatusCode());

        @SuppressWarnings("unchecked")
        OAuth2AccessToken accessToken = DefaultOAuth2AccessToken.valueOf(response.getBody());
        return accessToken;
    }

    private OAuth2AccessToken getUserAccessToken(String clientId, String clientSecret, String username, String password, String scope) {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add("grant_type", "password");
        formData.add("client_id", clientId);
        formData.add("scope", scope);
        formData.add("username", username);
        formData.add("password", password);
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        headers.set("Authorization",
            "Basic " + new String(Base64.encode(String.format("%s:%s", clientId, clientSecret).getBytes())));

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap("/oauth/token", formData, headers);
        assertEquals(HttpStatus.OK, response.getStatusCode());

        @SuppressWarnings("unchecked")
        OAuth2AccessToken accessToken = DefaultOAuth2AccessToken.valueOf(response.getBody());
        return accessToken;

    }

    public ClientDetails getClient(String id) throws Exception {
        HttpHeaders headers = getAuthenticatedHeaders(getClientCredentialsAccessToken("clients.read"));
        ResponseEntity<BaseClientDetails> result =
            serverRunning.getRestTemplate().exchange(
                serverRunning.getUrl("/oauth/clients/" + id),
                HttpMethod.GET,
                new HttpEntity<Void>(null, headers),
                BaseClientDetails.class);


        if (result.getStatusCode() == HttpStatus.NOT_FOUND) {
            return null;
        } else if (result.getStatusCode() == HttpStatus.OK) {
            return result.getBody();
        } else {
            throw new InvalidClientDetailsException("Unknown status code:" + result.getStatusCode());
        }

    }

    public boolean validateClients(BaseClientDetails[] expected, BaseClientDetails[] actual) {
        assertNotNull(expected);
        assertNotNull(actual);
        assertEquals(expected.length, actual.length);
        for (int i = 0; i < expected.length; i++) {
            assertNotNull(expected[i]);
            assertNotNull(actual[i]);
            assertEquals(expected[i].getClientId(), actual[i].getClientId());
        }
        return true;
    }

    private static class ClientIdComparator implements Comparator<BaseClientDetails> {
        @Override
        public int compare(BaseClientDetails o1, BaseClientDetails o2) {
            return (o1.getClientId().compareTo(o2.getClientId()));
        }

        @Override
        public boolean equals(Object obj) {
            return obj == this;
        }
    }

}
