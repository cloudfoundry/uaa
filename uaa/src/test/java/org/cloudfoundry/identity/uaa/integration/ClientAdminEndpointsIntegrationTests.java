/*
 * *****************************************************************************
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
import org.cloudfoundry.identity.uaa.ServerRunningExtension;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.client.InvalidClientDetailsException;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsCreation;
import org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsModification;
import org.cloudfoundry.identity.uaa.oauth.client.ClientJwtChangeRequest;
import org.cloudfoundry.identity.uaa.oauth.client.SecretChangeRequest;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidClientException;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.resources.SearchResults;
import org.cloudfoundry.identity.uaa.test.TestAccountExtension;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.zone.ClientSecretPolicy;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.doesSupportZoneDNS;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;

/**
 * @author Dave Syer
 * @author Luke Taylor
 */
public class ClientAdminEndpointsIntegrationTests {

    public static final String SECRET_TOO_LONG = "adfdfdasgdasgasdgafsgasfgfasgfadsgfagsagasddsafdsafsdfdafsdafdsfasdffasfasdfasdfdsfds" +
            "ewrewrewqrweqrewqrewqrewerwqqweewqrdsadsfewqrewqrtewrewrewrewrererererererererererdfadsafasfdasfsdaf" +
            "dsfasdfdsagfdsao43o4p43adfsfasdvcdasfmdsafzxcvaddsaaddfsafdsafdsfdsdfsfdsfdsasdfadfsadfsasadfsdfadfs";
    private static final Base64.Encoder ENCODER = Base64.getEncoder();

    @RegisterExtension
    private static final ServerRunningExtension serverRunning = ServerRunningExtension.connect();

    private static final UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @RegisterExtension
    private static final TestAccountExtension testAccountExtension = TestAccountExtension.standard(serverRunning, testAccounts);

    private OAuth2AccessToken token;
    private HttpHeaders headers;
    private List<ClientDetailsModification> clientDetailsModifications;

    @BeforeEach
    void setUp() {
        token = getClientCredentialsAccessToken("clients.read,clients.write,clients.admin");
        headers = getAuthenticatedHeaders(token);
    }

    @Test
    void getClient() {
        HttpHeaders myHeaders = getAuthenticatedHeaders(getClientCredentialsAccessToken("clients.read"));
        ResponseEntity<String> result = serverRunning.getForString("/oauth/clients/cf", myHeaders);
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(result.getBody()).contains("cf");
    }

    @Test
    void listClients() {
        HttpHeaders myHeaders = getAuthenticatedHeaders(getClientCredentialsAccessToken("clients.read"));
        ResponseEntity<String> result = serverRunning.getForString("/oauth/clients", myHeaders);
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(result.getBody()).contains("\"client_id\":\"cf\"")
                .doesNotContain("secret\":");
    }

    @BeforeEach
    void setupClients() {
        clientDetailsModifications = new ArrayList<>();
    }

    @AfterEach
    void teardownClients() {
        for (ClientDetailsModification clientDetailsModification : clientDetailsModifications) {
            serverRunning.getRestTemplate()
                    .exchange(serverRunning.getUrl("/oauth/clients/{client}"), HttpMethod.DELETE,
                            new HttpEntity<UaaClientDetails>(clientDetailsModification, headers), Void.class,
                            clientDetailsModification.getClientId());
        }
    }

    @Test
    void listClientsWithExtremePaginationDefaultsTo500() throws Exception {
        for (int i = 0; i < 502; i++) {
            clientDetailsModifications.add(createClient("client_credentials"));
        }

        HttpHeaders myHeaders = getAuthenticatedHeaders(getClientCredentialsAccessToken("clients.read"));
        ResponseEntity<String> result = serverRunning.getForString("/oauth/clients?count=3000", myHeaders);
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);

        SearchResults searchResults = new ObjectMapper().readValue(result.getBody(), SearchResults.class);
        assertThat(searchResults.getItemsPerPage()).isEqualTo(500);
        assertThat(searchResults.getResources()).hasSize(500);
        assertThat(searchResults.getTotalResults()).isGreaterThan(500);
    }

    @Test
    void testCreateClient() {
        createClient("client_credentials");
    }

    @Test
    void createClientWithSecondarySecret() {
        OAuth2AccessToken myToken = getClientCredentialsAccessToken("clients.read,clients.write");
        HttpHeaders myHeaders = getAuthenticatedHeaders(myToken);
        var client = new ClientDetailsCreation();
        client.setClientId(new RandomValueStringGenerator().generate());
        client.setClientSecret("primarySecret");
        client.setSecondaryClientSecret("secondarySecret");
        client.setAuthorizedGrantTypes(List.of("client_credentials"));

        ResponseEntity<Void> result = serverRunning.getRestTemplate()
                .exchange(serverRunning.getUrl("/oauth/clients"), HttpMethod.POST,
                        new HttpEntity<>(client, myHeaders), Void.class);
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    }

    @Test
    void createClientWithEmptySecret() {
        OAuth2AccessToken myToken = getClientCredentialsAccessToken("clients.admin");
        HttpHeaders myHeaders = getAuthenticatedHeaders(myToken);
        var client = new ClientDetailsCreation();
        client.setClientId(new RandomValueStringGenerator().generate());
        client.setClientSecret(UaaStringUtils.EMPTY_STRING);
        client.setAuthorizedGrantTypes(List.of("password"));

        ResponseEntity<Void> result = serverRunning.getRestTemplate()
                .exchange(serverRunning.getUrl("/oauth/clients"), HttpMethod.POST,
                        new HttpEntity<>(client, myHeaders), Void.class);
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    }

    @Test
    void createClients() {
        doCreateClients();
    }

    @Test
    void createClientWithValidLongRedirectUris() {
        // redirectUri shorter than the database column size
        HashSet<String> uris = new HashSet<>();
        for (int i = 0; i < 666; ++i) {
            uris.add("http://example.com/myuri/foo/bar/abcdefg/abcdefg" + i);
        }

        UaaClientDetails client = createClientWithSecretAndRedirectUri("secret", uris, "client_credentials");
        ResponseEntity<Void> result = serverRunning.getRestTemplate().exchange(serverRunning.getUrl("/oauth/clients"),
                HttpMethod.POST, new HttpEntity<>(client, headers), Void.class);
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    }

    public ClientDetailsModification[] doCreateClients() {
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
                        new HttpEntity<>(clients, headers),
                        ClientDetailsModification[].class);
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        validateClients(clients, result.getBody());
        for (String id : ids) {
            ClientDetails client = getClient(id);
            assertThat(client).isNotNull();
        }
        return result.getBody();
    }

    @Test
    void createClientWithCommaDelimitedScopesValidatesAllTheScopes() {
        // log in as admin
        OAuth2AccessToken adminToken = getClientCredentialsAccessToken("");
        HttpHeaders adminHeaders = getAuthenticatedHeaders(adminToken);

        // make client that can create other clients
        String newClientId = new RandomValueStringGenerator().generate();
        UaaClientDetails clientCreator = new UaaClientDetails(
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
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.CREATED);

        // log in as new client
        OAuth2AccessToken myToken = getClientCredentialsAccessToken(clientCreator.getClientId(), clientCreator.getClientSecret(), "");
        HttpHeaders myHeaders = getAuthenticatedHeaders(myToken);

        // make client with restricted scopes
        UaaClientDetails invalidClient = new UaaClientDetails(
                new RandomValueStringGenerator().generate(),
                "",
                newClientId + ".admin,uaa.admin",
                "client_credentials",
                "uaa.none"
        );
        invalidClient.setClientSecret("secret");
        ResponseEntity<InvalidClientException> invalidClientRequest = serverRunning.getRestTemplate().exchange(
                serverRunning.getUrl("/oauth/clients"), HttpMethod.POST,
                new HttpEntity<>(invalidClient, myHeaders), InvalidClientException.class);

        // ensure correct failure
        assertThat(invalidClientRequest.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(invalidClientRequest.getBody().getOAuth2ErrorCode()).isEqualTo("invalid_client");
        assertThat(invalidClientRequest.getBody().getMessage()).as("Error message is unexpected").startsWith("uaa.admin is not an allowed scope for caller");
    }

    @Test
    void createClientWithoutSecretIsRejected() {
        OAuth2AccessToken myToken = getClientCredentialsAccessToken("clients.read,clients.write");
        HttpHeaders myHeaders = getAuthenticatedHeaders(myToken);
        UaaClientDetails invalidSecretClient = new UaaClientDetails(new RandomValueStringGenerator().generate(), "", "foo,bar",
                "client_credentials", "uaa.none");
        invalidSecretClient.setClientSecret("tooLongSecret");
        ResponseEntity<InvalidClientException> result = serverRunning.getRestTemplate().exchange(
                serverRunning.getUrl("/oauth/clients"), HttpMethod.POST,
                new HttpEntity<>(invalidSecretClient, myHeaders), InvalidClientException.class);
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(result.getBody().getOAuth2ErrorCode()).isEqualTo("invalid_client");
    }

    @Test
    void createClientWithTooLongSecretIsRejected() {
        OAuth2AccessToken myToken = getClientCredentialsAccessToken("clients.read,clients.write");
        HttpHeaders myHeaders = getAuthenticatedHeaders(myToken);
        UaaClientDetails client = new UaaClientDetails(new RandomValueStringGenerator().generate(), "", "foo,bar",
                "client_credentials", "uaa.none");
        client.setClientSecret(SECRET_TOO_LONG);
        ResponseEntity<InvalidClientException> result = serverRunning.getRestTemplate().exchange(
                serverRunning.getUrl("/oauth/clients"), HttpMethod.POST,
                new HttpEntity<>(client, myHeaders), InvalidClientException.class);
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(result.getBody().getOAuth2ErrorCode()).isEqualTo("invalid_client");
    }

    @Test
    void createClientWithTooLongSecondarySecretIsRejected() {
        OAuth2AccessToken myToken = getClientCredentialsAccessToken("clients.read,clients.write");
        HttpHeaders myHeaders = getAuthenticatedHeaders(myToken);
        var client = new ClientDetailsCreation();
        client.setClientId(new RandomValueStringGenerator().generate());
        client.setClientSecret("primarySecret");
        client.setSecondaryClientSecret(SECRET_TOO_LONG);
        client.setAuthorizedGrantTypes(List.of("client_credentials"));

        ResponseEntity<InvalidClientException> result = serverRunning.getRestTemplate().exchange(
                serverRunning.getUrl("/oauth/clients"), HttpMethod.POST,
                new HttpEntity<>(client, myHeaders), InvalidClientException.class);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(result.getBody().getOAuth2ErrorCode()).isEqualTo("invalid_client");
    }

    @Test
    void createClientWithStrictSecretPolicyTest() {
        assertThat(doesSupportZoneDNS()).as("Expected testzone1.localhost and testzone2.localhost to resolve to 127.0.0.1").isTrue();
        String testZoneId = "testzone1";

        IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(serverRunning.getBaseUrl(), new String[0], "admin", "adminsecret"));
        RestTemplate identityClient = IntegrationTestUtils
                .getClientCredentialsTemplate(IntegrationTestUtils.getClientCredentialsResource(serverRunning.getBaseUrl(),
                        new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret"));

        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        //min length 5, max length 12, requires 1 uppercase lowercase digit and specialChar, expries 6 months.
        config.setClientSecretPolicy(new ClientSecretPolicy(5, 12, 1, 1, 1, 1, 6));
        IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, serverRunning.getBaseUrl(), testZoneId, testZoneId, config);


        UaaClientDetails client = new UaaClientDetails(new RandomValueStringGenerator().generate(), "", "foo,bar",
                "client_credentials", "uaa.none");
        client.setClientSecret("Secret1@");

        String zoneAdminToken = IntegrationTestUtils.getZoneAdminToken(serverRunning.getBaseUrl(), serverRunning, testZoneId);
        HttpHeaders xZoneHeaders = getAuthenticatedHeaders(zoneAdminToken);
        xZoneHeaders.add(IdentityZoneSwitchingFilter.HEADER, testZoneId);
        ResponseEntity<UaaException> result = serverRunning.getRestTemplate().exchange(
                serverRunning.getBaseUrl() + "/oauth/clients", HttpMethod.POST,
                new HttpEntity<>(client, xZoneHeaders), UaaException.class);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.CREATED);

        //Negative Test
        UaaClientDetails failClient = new UaaClientDetails(new RandomValueStringGenerator().generate(), "", "foo,bar",
                "client_credentials", "uaa.none");
        failClient.setClientSecret("badsecret");
        result = serverRunning.getRestTemplate().exchange(
                serverRunning.getBaseUrl() + "/oauth/clients", HttpMethod.POST,
                new HttpEntity<>(failClient, xZoneHeaders), UaaException.class);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);

        //cleanup
        config.setClientSecretPolicy(new ClientSecretPolicy(0, 255, 0, 0, 0, 0, 6));
        IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, serverRunning.getBaseUrl(), testZoneId, testZoneId, config);
    }

    @Test
    void clientSecretExpiryCannotBeSet() {
        assertThat(doesSupportZoneDNS()).as("Expected testzone1.localhost and testzone2.localhost to resolve to 127.0.0.1").isTrue();
        String testZoneId = "testzone1";

        IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(serverRunning.getBaseUrl(), new String[0], "admin", "adminsecret"));
        RestTemplate identityClient = IntegrationTestUtils
                .getClientCredentialsTemplate(IntegrationTestUtils.getClientCredentialsResource(serverRunning.getBaseUrl(),
                        new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret"));

        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        //min length 5, max length 12, requires 1 uppercase lowercase digit and specialChar, expries 6 months.
        config.setClientSecretPolicy(new ClientSecretPolicy(5, 12, 1, 1, 1, 1, 6));
        IdentityZone createdZone = IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, serverRunning.getBaseUrl(), testZoneId, testZoneId, config);
        assertThat(createdZone.getConfig().getClientSecretPolicy().getExpireSecretInMonths()).isEqualTo(-1);
        config.setClientSecretPolicy(new ClientSecretPolicy(0, 255, 0, 0, 0, 0, 6));
        IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, serverRunning.getBaseUrl(), testZoneId, testZoneId, config);
    }

    @Test
    void nonImplicitGrantClientWithSecret() {
        headers = getAuthenticatedHeaders(getClientCredentialsAccessToken("clients.admin,clients.read,clients.write,clients.secret"));
        headers.add("Accept", "application/json");
        String grantTypes = "client_credentials";
        RandomValueStringGenerator gen = new RandomValueStringGenerator();
        String[] ids = new String[5];
        UaaClientDetails[] clients = new UaaClientDetails[ids.length];
        for (int i = 0; i < ids.length; i++) {
            ids[i] = gen.generate();
            clients[i] = new UaaClientDetails(ids[i], "", "foo,bar", grantTypes, "uaa.none");
            clients[i].setClientSecret("secret");
            clients[i].setAdditionalInformation(Collections.<String, Object>singletonMap("foo",
                    Collections.singletonList("bar")));
        }
        clients[clients.length - 1].setClientSecret(null);
        ResponseEntity<UaaException> result =
                serverRunning.getRestTemplate().exchange(
                        serverRunning.getUrl("/oauth/clients/tx"),
                        HttpMethod.POST,
                        new HttpEntity<>(clients, headers),
                        UaaException.class);
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        for (String id : ids) {
            ClientDetails client = getClient(id);
            assertThat(client).isNotNull();
        }
    }

    @Test
    void duplicateIdsIsRejectedTxFails() {
        headers = getAuthenticatedHeaders(getClientCredentialsAccessToken("clients.admin,clients.read,clients.write,clients.secret"));
        headers.add("Accept", "application/json");
        String grantTypes = "client_credentials";
        RandomValueStringGenerator gen = new RandomValueStringGenerator();
        String[] ids = new String[5];
        UaaClientDetails[] clients = new UaaClientDetails[ids.length];
        for (int i = 0; i < ids.length; i++) {
            ids[i] = gen.generate();
            clients[i] = new UaaClientDetails(ids[i], "", "foo,bar", grantTypes, "uaa.none");
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
                        new HttpEntity<>(clients, headers),
                        UaaException.class);
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        for (String id : ids) {
            ClientDetails client = getClient(id);
            assertThat(client).isNull();
        }
    }

    @Test
    void implicitAndAuthCodeGrantClient() {
        UaaClientDetails client = new UaaClientDetails(new RandomValueStringGenerator().generate(), "", "foo,bar",
                "implicit,authorization_code", "uaa.none");
        ResponseEntity<InvalidClientException> result = serverRunning.getRestTemplate().exchange(
                serverRunning.getUrl("/oauth/clients"), HttpMethod.POST,
                new HttpEntity<>(client, headers), InvalidClientException.class);
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(result.getBody().getOAuth2ErrorCode()).isEqualTo("invalid_client");
    }

    @Test
    void implicitGrantClientWithoutSecretIsOk() {
        UaaClientDetails client = new UaaClientDetails(new RandomValueStringGenerator().generate(), "", "foo,bar",
                "implicit", "uaa.none", "http://redirect.url");
        ResponseEntity<Void> result = serverRunning.getRestTemplate().exchange(serverRunning.getUrl("/oauth/clients"),
                HttpMethod.POST, new HttpEntity<>(client, headers), Void.class);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    }

    @Test
    void passwordGrantClientWithoutSecretIsOk() {
        UaaClientDetails client = new UaaClientDetails(new RandomValueStringGenerator().generate(), "", "foo,bar",
                "password", "uaa.none", "http://redirect.url");
        ResponseEntity<Void> result = serverRunning.getRestTemplate().exchange(serverRunning.getUrl("/oauth/clients"),
                HttpMethod.POST, new HttpEntity<>(client, headers), Void.class);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    }

    @Test
    void authzCodeGrantAutomaticallyAddsRefreshToken() {
        UaaClientDetails client = createClient(GRANT_TYPE_AUTHORIZATION_CODE);

        ResponseEntity<String> result = serverRunning.getForString("/oauth/clients/" + client.getClientId(), headers);
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(result.getBody()).contains("\"authorized_grant_types\":[\"authorization_code\",\"refresh_token\"]");
    }

    @Test
    void passwordGrantAutomaticallyAddsRefreshToken() {
        UaaClientDetails client = createClient("password");

        ResponseEntity<String> result = serverRunning.getForString("/oauth/clients/" + client.getClientId(), headers);
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(result.getBody()).contains("\"authorized_grant_types\":[\"password\",\"refresh_token\"]");
    }

    @Test
    void updateClient() {
        UaaClientDetails client = createClient("client_credentials");

        client.setResourceIds(Collections.singleton("foo"));
        client.setClientSecret(null);
        client.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("some.crap"));
        client.setAccessTokenValiditySeconds(60);
        client.setRefreshTokenValiditySeconds(120);
        client.setAdditionalInformation(Collections.<String, Object>singletonMap("foo",
                Collections.singletonList("rab")));

        ResponseEntity<Void> result = serverRunning.getRestTemplate().exchange(
                serverRunning.getUrl("/oauth/clients/{client}"),
                HttpMethod.PUT, new HttpEntity<>(client, headers), Void.class,
                client.getClientId());
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);

        ResponseEntity<String> response = serverRunning.getForString("/oauth/clients/" + client.getClientId(), headers);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        String body = response.getBody();
        assertThat(body).contains(client.getClientId())
                .contains("some.crap")
                .contains("refresh_token_validity\":120")
                .contains("access_token_validity\":60")
                .as("Wrong body: " + body).contains("\"foo\":[\"rab\"]");
    }

    @Test
    void updateClients() {
        UaaClientDetails[] clients = doCreateClients();
        headers = getAuthenticatedHeaders(getClientCredentialsAccessToken("clients.admin,clients.read,clients.write,clients.secret"));
        headers.add("Accept", "application/json");
        for (UaaClientDetails c : clients) {
            c.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("some.crap"));
            c.setAccessTokenValiditySeconds(60);
            c.setRefreshTokenValiditySeconds(120);
        }
        ResponseEntity<UaaClientDetails[]> result =
                serverRunning.getRestTemplate().exchange(
                        serverRunning.getUrl("/oauth/clients/tx"),
                        HttpMethod.PUT,
                        new HttpEntity<>(clients, headers),
                        UaaClientDetails[].class);
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        validateClients(clients, result.getBody());
        for (UaaClientDetails c : clients) {
            ClientDetails client = getClient(c.getClientId());
            assertThat(client).isNotNull();
            assertThat(client.getRefreshTokenValiditySeconds()).isEqualTo((Integer) 120);
            assertThat(client.getAccessTokenValiditySeconds()).isEqualTo((Integer) 60);
        }
    }

    @Test
    void deleteClients() {
        UaaClientDetails[] clients = doCreateClients();
        headers = getAuthenticatedHeaders(getClientCredentialsAccessToken("clients.admin,clients.read,clients.write,clients.secret,clients.admin"));
        headers.add("Accept", "application/json");
        ResponseEntity<UaaClientDetails[]> result =
                serverRunning.getRestTemplate().exchange(
                        serverRunning.getUrl("/oauth/clients/tx/delete"),
                        HttpMethod.POST,
                        new HttpEntity<>(clients, headers),
                        UaaClientDetails[].class);
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        validateClients(clients, result.getBody());
        for (UaaClientDetails c : clients) {
            ClientDetails client = getClient(c.getClientId());
            assertThat(client).isNull();
        }
    }

    @Test
    void deleteClientsMissingId() {
        UaaClientDetails[] clients = doCreateClients();
        headers = getAuthenticatedHeaders(getClientCredentialsAccessToken("clients.admin,clients.read,clients.write,clients.secret,clients.admin"));
        headers.add("Accept", "application/json");
        String oldId = clients[clients.length - 1].getClientId();
        clients[clients.length - 1].setClientId("unknown.id");
        ResponseEntity<UaaClientDetails[]> result =
                serverRunning.getRestTemplate().exchange(
                        serverRunning.getUrl("/oauth/clients/tx/delete"),
                        HttpMethod.POST,
                        new HttpEntity<>(clients, headers),
                        UaaClientDetails[].class);
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        clients[clients.length - 1].setClientId(oldId);
        for (UaaClientDetails c : clients) {
            ClientDetails client = getClient(c.getClientId());
            assertThat(client).isNotNull();
        }
    }

    @Test
    void changeSecret() {
        headers = getAuthenticatedHeaders(getClientCredentialsAccessToken("clients.read,clients.write,clients.secret,uaa.admin"));
        UaaClientDetails client = createClient("client_credentials");

        client.setResourceIds(Collections.singleton("foo"));

        SecretChangeRequest change = new SecretChangeRequest();
        change.setOldSecret(client.getClientSecret());
        change.setSecret("newsecret");
        ResponseEntity<Void> result = serverRunning.getRestTemplate().exchange(
                serverRunning.getUrl("/oauth/clients/{client}/secret"),
                HttpMethod.PUT, new HttpEntity<>(change, headers), Void.class,
                client.getClientId());
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void changeJwtConfig() {
        headers = getAuthenticatedHeaders(getClientCredentialsAccessToken("clients.read,clients.write,clients.trust,uaa.admin"));
        UaaClientDetails client = createClient("client_credentials");

        client.setResourceIds(Collections.singleton("foo"));

        ClientJwtChangeRequest def = new ClientJwtChangeRequest(null, null, null);
        def.setJsonWebKeyUri("http://localhost:8080/uaa/token_key");
        def.setClientId("admin");

        ResponseEntity<Void> result = serverRunning.getRestTemplate().exchange(
                serverRunning.getUrl("/oauth/clients/{client}/clientjwt"),
                HttpMethod.PUT, new HttpEntity<>(def, headers), Void.class,
                client.getClientId());
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void testChangeFederatedJwtConfig() {
        headers = getAuthenticatedHeaders(getClientCredentialsAccessToken("clients.read,clients.write,clients.trust,uaa.admin"));
        UaaClientDetails client = createClient("client_credentials");

        client.setResourceIds(Collections.singleton("foo"));

        ClientJwtChangeRequest def = new ClientJwtChangeRequest("admin", "http://localhost:8080/uaa/token_key", null);
        ResponseEntity<Void> result = serverRunning.getRestTemplate().exchange(
                serverRunning.getUrl("/oauth/clients/{client}/clientjwt"),
                HttpMethod.PUT, new HttpEntity<>(def, headers), Void.class,
                client.getClientId());
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);

        def = new ClientJwtChangeRequest();
        def.setIssuer("http://localhost:8080/uaa");
        def.setSubject("client-admin-id");
        def.setClientId("admin");

        result = serverRunning.getRestTemplate().exchange(
                serverRunning.getUrl("/oauth/clients/{client}/clientjwt"),
                HttpMethod.PUT, new HttpEntity<>(def, headers), Void.class,
                client.getClientId());
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void testChangeJwtConfigNoAuthorization() {
        headers = getAuthenticatedHeaders(getClientCredentialsAccessToken("clients.read,clients.write,clients.trust,uaa.admin"));
        UaaClientDetails client = createClient("client_credentials");
        headers = getAuthenticatedHeaders(getClientCredentialsAccessToken("clients.read,clients.write"));

        client.setResourceIds(Collections.singleton("foo"));

        ClientJwtChangeRequest def = new ClientJwtChangeRequest(null, null, null);
        def.setJsonWebKeyUri("http://localhost:8080/uaa/token_key");
        def.setClientId("admin");

        ResponseEntity<Void> result = serverRunning.getRestTemplate().exchange(
                serverRunning.getUrl("/oauth/clients/{client}/clientjwt"),
                HttpMethod.PUT, new HttpEntity<>(def, headers), Void.class,
                client.getClientId());
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void changeJwtConfigInvalidTokenKey() {
        headers = getAuthenticatedHeaders(getClientCredentialsAccessToken("clients.read,clients.write,clients.secret,uaa.admin"));
        UaaClientDetails client = createClient("client_credentials");

        client.setResourceIds(Collections.singleton("foo"));

        ClientJwtChangeRequest def = new ClientJwtChangeRequest(null, null, null);
        def.setJsonWebKeyUri("no uri");
        def.setClientId("admin");

        ResponseEntity<Void> result = serverRunning.getRestTemplate().exchange(
                serverRunning.getUrl("/oauth/clients/{client}/clientjwt"),
                HttpMethod.PUT, new HttpEntity<>(def, headers), Void.class,
                client.getClientId());
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void createClientsWithStrictSecretPolicy() {
        headers = getAuthenticatedHeaders(getClientCredentialsAccessToken("clients.read,clients.write,clients.secret,uaa.admin"));
        UaaClientDetails client = createClient("client_credentials");

        client.setResourceIds(Collections.singleton("foo"));

        SecretChangeRequest change = new SecretChangeRequest();
        change.setOldSecret(client.getClientSecret());
        change.setSecret(SECRET_TOO_LONG);
        ResponseEntity<Void> result = serverRunning.getRestTemplate().exchange(
                serverRunning.getUrl("/oauth/clients/{client}/secret"),
                HttpMethod.PUT, new HttpEntity<>(change, headers), Void.class,
                client.getClientId());
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void deleteClient() {
        UaaClientDetails client = createClient("client_credentials");

        client.setResourceIds(Collections.singleton("foo"));

        ResponseEntity<Void> result = serverRunning.getRestTemplate()
                .exchange(serverRunning.getUrl("/oauth/clients/{client}"), HttpMethod.DELETE,
                        new HttpEntity<>(client, headers), Void.class,
                        client.getClientId());
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void addUpdateAndDeleteTx() {
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
        ResponseEntity<UaaClientDetails[]> result =
                serverRunning.getRestTemplate().exchange(
                        serverRunning.getUrl("/oauth/clients/tx/modify"),
                        HttpMethod.POST,
                        new HttpEntity<>(clients, headers),
                        UaaClientDetails[].class);
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        //set the deleted client ID so we can verify it is gone.
        clients[clients.length - 1].setClientId(oldId);
        for (int i = 0; i < clients.length; i++) {
            ClientDetails client = getClient(clients[i].getClientId());
            if (i == (clients.length - 1)) {
                assertThat(client).isNull();
            } else {
                assertThat(client).isNotNull();
            }
        }
    }

    @Test
        // CFID-372
    void createExistingClientFails() {
        UaaClientDetails client = createClient("client_credentials");

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> attempt = serverRunning.getRestTemplate().exchange(serverRunning.getUrl("/oauth/clients"),
                HttpMethod.POST, new HttpEntity<>(client, headers), Map.class);
        assertThat(attempt.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        @SuppressWarnings("unchecked")
        Map<String, String> map = attempt.getBody();
        assertThat(map).containsEntry("error", "invalid_client");
    }

    @Test
    void clientApprovalsDeleted() {
        //create client
        UaaClientDetails client = createClient("client_credentials", "password");
        assertThat(getClient(client.getClientId())).isNotNull();
        //issue a user token for this client
        OAuth2AccessToken userToken = getUserAccessToken(client.getClientId(), "secret", testAccounts.getUserName(), testAccounts.getPassword(), "oauth.approvals");
        //make sure we don't have any approvals
        Approval[] approvals = getApprovals(userToken.getValue(), client.getClientId());
        assertThat(approvals).isEmpty();
        //create three approvals
        addApprovals(userToken.getValue(), client.getClientId());
        approvals = getApprovals(userToken.getValue(), client.getClientId());
        assertThat(approvals).hasSize(3);
        //delete the client
        ResponseEntity<Void> result = serverRunning.getRestTemplate().exchange(serverRunning.getUrl("/oauth/clients/{client}"), HttpMethod.DELETE,
                new HttpEntity<>(client, getAuthenticatedHeaders(token)), Void.class, client.getClientId());
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);

        //create a client that can read another clients approvals
        String deletedClientId = client.getClientId();
        client = createApprovalsClient("password");
        userToken = getUserAccessToken(client.getClientId(), "secret", testAccounts.getUserName(), testAccounts.getPassword(), "oauth.approvals");
        //make sure we don't have any approvals
        approvals = getApprovals(userToken.getValue(), deletedClientId);
        assertThat(approvals).isEmpty();
        assertThat(getClient(deletedClientId)).isNull();
    }

    @Test
    void clientTxApprovalsDeleted() {
        //create client
        UaaClientDetails client = createClient("client_credentials", "password");
        assertThat(getClient(client.getClientId())).isNotNull();
        //issue a user token for this client
        OAuth2AccessToken userToken = getUserAccessToken(client.getClientId(), "secret", testAccounts.getUserName(), testAccounts.getPassword(), "oauth.approvals");
        //make sure we don't have any approvals
        Approval[] approvals = getApprovals(userToken.getValue(), client.getClientId());
        assertThat(approvals).isEmpty();
        //create three approvals
        addApprovals(userToken.getValue(), client.getClientId());
        approvals = getApprovals(userToken.getValue(), client.getClientId());
        assertThat(approvals).hasSize(3);
        //delete the client
        ResponseEntity<Void> result = serverRunning.getRestTemplate().exchange(serverRunning.getUrl("/oauth/clients/tx/delete"), HttpMethod.POST,
                new HttpEntity<>(new UaaClientDetails[]{client}, getAuthenticatedHeaders(getClientCredentialsAccessToken("clients.admin"))), Void.class);
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        //create a client that can read another clients approvals
        String deletedClientId = client.getClientId();
        client = createApprovalsClient("password");
        userToken = getUserAccessToken(client.getClientId(), "secret", testAccounts.getUserName(), testAccounts.getPassword(), "oauth.approvals");
        //make sure we don't have any approvals
        approvals = getApprovals(userToken.getValue(), deletedClientId);
        assertThat(approvals).isEmpty();
        assertThat(getClient(deletedClientId)).isNull();
    }

    @Test
    void clientTxModifyApprovalsDeleted() {
        //create client
        ClientDetailsModification client = createClient("client_credentials", "password");
        assertThat(getClient(client.getClientId())).isNotNull();
        //issue a user token for this client
        OAuth2AccessToken userToken = getUserAccessToken(client.getClientId(), "secret", testAccounts.getUserName(), testAccounts.getPassword(), "oauth.approvals");
        //make sure we don't have any approvals
        Approval[] approvals = getApprovals(userToken.getValue(), client.getClientId());
        assertThat(approvals).isEmpty();
        //create three approvals
        addApprovals(userToken.getValue(), client.getClientId());
        approvals = getApprovals(userToken.getValue(), client.getClientId());
        assertThat(approvals).hasSize(3);
        //delete the client
        client.setAction(ClientDetailsModification.DELETE);
        ResponseEntity<Void> result = serverRunning.getRestTemplate().exchange(serverRunning.getUrl("/oauth/clients/tx/modify"), HttpMethod.POST,
                new HttpEntity<>(new UaaClientDetails[]{client}, getAuthenticatedHeaders(getClientCredentialsAccessToken("clients.admin"))), Void.class);
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.OK);
        //create a client that can read another clients approvals
        String deletedClientId = client.getClientId();
        client = createApprovalsClient("password");
        userToken = getUserAccessToken(client.getClientId(), "secret", testAccounts.getUserName(), testAccounts.getPassword(), "oauth.approvals");
        //make sure we don't have any approvals
        approvals = getApprovals(userToken.getValue(), deletedClientId);
        assertThat(approvals).isEmpty();
        assertThat(getClient(deletedClientId)).isNull();
    }

    private Approval[] getApprovals(String token, String clientId) {
        String filter = "client_id eq \"" + clientId + "\"";
        HttpHeaders myHeaders = getAuthenticatedHeaders(token);

        ResponseEntity<Approval[]> approvals =
                serverRunning.getRestTemplate().exchange(serverRunning.getUrl("/approvals"),
                        HttpMethod.GET,
                        new HttpEntity<>(myHeaders),
                        Approval[].class,
                        filter);
        assertThat(approvals.getStatusCode()).isEqualTo(HttpStatus.OK);
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

        HttpHeaders myHeaders = getAuthenticatedHeaders(token);
        HttpEntity<Approval[]> entity = new HttpEntity<>(approvals, myHeaders);
        ResponseEntity<Approval[]> response = serverRunning.getRestTemplate().exchange(
                serverRunning.getUrl("/approvals/{clientId}"),
                HttpMethod.PUT,
                entity,
                Approval[].class,
                clientId);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        return response.getBody();
    }

    private ClientDetailsModification createClient(String... grantTypes) {
        return createClientWithSecret("secret", grantTypes);
    }

    private ClientDetailsModification createClientWithSecretAndRedirectUri(
            String secret, Set<String> redirectUris, String... grantTypes) {
        ClientDetailsModification client = new ClientDetailsModification();
        client.setClientId(new RandomValueStringGenerator().generate());
        client.setScope(Arrays.asList("oauth.approvals", "foo", "bar"));
        client.setAuthorizedGrantTypes(Arrays.asList(grantTypes));
        client.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("uaa.none"));
        client.setClientSecret(secret);
        client.setAdditionalInformation(Collections.<String, Object>singletonMap("foo",
                Collections.singletonList("bar")));
        client.setRegisteredRedirectUri(redirectUris == null ?
                Collections.singleton("http://redirect.url") : redirectUris);
        return client;
    }

    private ClientDetailsModification createClientWithSecret(String secret, String... grantTypes) {
        ClientDetailsModification client =
                createClientWithSecretAndRedirectUri(secret,
                        Collections.singleton("http://redirect.url"), grantTypes);
        ResponseEntity<Void> result = serverRunning.getRestTemplate().exchange(serverRunning.getUrl("/oauth/clients"),
                HttpMethod.POST, new HttpEntity<UaaClientDetails>(client, headers), Void.class);
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        return client;
    }

    private ClientDetailsModification createApprovalsClient(String... grantTypes) {
        ClientDetailsModification client = createClientWithSecretAndRedirectUri("secret",
                Collections.singleton("http://redirect.url"), grantTypes);
        ResponseEntity<Void> result = serverRunning.getRestTemplate().exchange(serverRunning.getUrl("/oauth/clients"),
                HttpMethod.POST, new HttpEntity<UaaClientDetails>(client, headers), Void.class);
        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        return client;
    }

    public HttpHeaders getAuthenticatedHeaders(OAuth2AccessToken token) {
        return getAuthenticatedHeaders(token.getValue());
    }

    public HttpHeaders getAuthenticatedHeaders(String token) {
        HttpHeaders myHeaders = new HttpHeaders();
        myHeaders.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        myHeaders.setContentType(MediaType.APPLICATION_JSON);
        myHeaders.set("Authorization", "Bearer " + token);
        return myHeaders;
    }

    private OAuth2AccessToken getClientCredentialsAccessToken(String scope) {
        String clientId = testAccounts.getAdminClientId();
        String clientSecret = testAccounts.getAdminClientSecret();

        return getClientCredentialsAccessToken(clientId, clientSecret, scope);
    }

    private OAuth2AccessToken getClientCredentialsAccessToken(String clientId, String clientSecret, String scope) {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", "client_credentials");
        formData.add("client_id", clientId);
        formData.add("scope", scope);
        HttpHeaders myHeaders = new HttpHeaders();
        myHeaders.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        myHeaders.set("Authorization",
                "Basic " + new String(ENCODER.encode("%s:%s".formatted(clientId, clientSecret).getBytes())));

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap("/oauth/token", formData, myHeaders);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

        @SuppressWarnings("unchecked")
        OAuth2AccessToken accessToken = DefaultOAuth2AccessToken.valueOf(response.getBody());
        return accessToken;
    }

    private OAuth2AccessToken getUserAccessToken(String clientId, String clientSecret, String username, String password, String scope) {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", "password");
        formData.add("client_id", clientId);
        formData.add("scope", scope);
        formData.add("username", username);
        formData.add("password", password);
        HttpHeaders myHeaders = new HttpHeaders();
        myHeaders.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        myHeaders.set("Authorization",
                "Basic " + new String(ENCODER.encode("%s:%s".formatted(clientId, clientSecret).getBytes())));

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap("/oauth/token", formData, myHeaders);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

        @SuppressWarnings("unchecked")
        OAuth2AccessToken accessToken = DefaultOAuth2AccessToken.valueOf(response.getBody());
        return accessToken;
    }

    public ClientDetails getClient(String id) {
        HttpHeaders myHeaders = getAuthenticatedHeaders(getClientCredentialsAccessToken("clients.read"));
        ResponseEntity<UaaClientDetails> result =
                serverRunning.getRestTemplate().exchange(
                        serverRunning.getUrl("/oauth/clients/" + id),
                        HttpMethod.GET,
                        new HttpEntity<Void>(null, myHeaders),
                        UaaClientDetails.class);

        if (result.getStatusCode() == HttpStatus.NOT_FOUND) {
            return null;
        } else if (result.getStatusCode() == HttpStatus.OK) {
            return result.getBody();
        } else {
            throw new InvalidClientDetailsException("Unknown status code:" + result.getStatusCode());
        }
    }

    public boolean validateClients(UaaClientDetails[] expected, UaaClientDetails[] actual) {
        assertThat(expected).isNotNull();
        assertThat(actual).hasSameSizeAs(expected);
        for (int i = 0; i < expected.length; i++) {
            assertThat(expected[i]).isNotNull();
            assertThat(actual[i]).isNotNull();
            assertThat(actual[i].getClientId()).isEqualTo(expected[i].getClientId());
        }
        return true;
    }
}
