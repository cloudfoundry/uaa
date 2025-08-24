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
package org.cloudfoundry.identity.uaa.test;

import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.client.DefaultOAuth2ClientContext;
import org.cloudfoundry.identity.uaa.oauth.client.OAuth2ClientContext;
import org.cloudfoundry.identity.uaa.oauth.client.OAuth2RestTemplate;
import org.cloudfoundry.identity.uaa.oauth.client.http.OAuth2ErrorHandler;
import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2ProtectedResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.token.AccessTokenRequest;
import org.cloudfoundry.identity.uaa.oauth.token.DefaultAccessTokenRequest;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.Assert;
import org.springframework.web.client.RestOperations;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * <pre>
 * &#064;RegisterExtension
 * public static final ServerRunningExtension serverRunning = ServerRunningExtension.connect();
 *
 * private static final UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);
 *
 * &#064;RegisterExtension
 * private static final TestAccountSetup testAccountSetup = TestAccountSetup.standard(serverRunning, testAccounts);
 * </pre>
 *
 * @author Dave Syer
 * @author Duane May
 */
public final class TestAccountExtension implements BeforeAllCallback {

    private static final Logger logger = LoggerFactory.getLogger(TestAccountExtension.class);

    private final UrlHelper serverRunning;

    private final UaaTestAccounts testAccounts;

    private UaaUser user;

    private static boolean initialized;

    private TestAccountExtension(UrlHelper serverRunning, UaaTestAccounts testAccounts) {
        this.serverRunning = serverRunning;
        this.testAccounts = testAccounts;
    }

    public static TestAccountExtension standard(UrlHelper serverRunning, UaaTestAccounts testAccounts) {
        return new TestAccountExtension(serverRunning, testAccounts);
    }

    @Override
    public void beforeAll(ExtensionContext context) {
        initializeIfNecessary();
    }

    /**
     * @return the user (if already created null otherwise)
     */
    public UaaUser getUser() {
        return user;
    }

    public UaaTestAccounts getTestAccounts() {
        return testAccounts;
    }

    private void initializeIfNecessary() {
        OAuth2ProtectedResourceDetails resource = testAccounts.getAdminClientCredentialsResource();
        OAuth2RestTemplate client = createRestTemplate(resource, new DefaultAccessTokenRequest());
        // Cache statically to save time on a test suite
        if (!initialized) {
            logger.info("Checking user account context for server={}", resource.getAccessTokenUri());
            if (!scimClientExists(client)) {
                createScimClient(client);
            }
            if (!appClientExists(client)) {
                createAppClient(client);
            }
            if (!cfClientExists(client)) {
                createCfClient(client);
            }
            initialized = true;
        }
        resource = testAccounts.getClientCredentialsResource("oauth.clients.scim", "scim", "scimsecret");
        client = createRestTemplate(resource, new DefaultAccessTokenRequest());
        initializeUserAccount(client);
    }

    private void createCfClient(RestOperations client) {
        UaaClientDetails clientDetails = new UaaClientDetails("cf", "cloud_controller,openid,password",
                "openid,cloud_controller.read,cloud_controller_service_permissions.read,password.write,scim.userids", "implicit", "uaa.none",
                "https://uaa.cloudfoundry.com/redirect/cf");
        createClient(client, testAccounts.getClientDetails("oauth.clients.cf", clientDetails));
    }

    private void createScimClient(RestOperations client) {
        UaaClientDetails clientDetails = new UaaClientDetails("scim", "oauth", "uaa.none", "client_credentials",
                "scim.read,scim.write,password.write,oauth.approvals", "http://some.redirect.url.com");
        clientDetails.setClientSecret("scimsecret");
        createClient(client, testAccounts.getClientDetails("oauth.clients.scim", clientDetails));
    }

    private void createAppClient(RestOperations client) {
        UaaClientDetails clientDetails = new UaaClientDetails("app", "none",
                "cloud_controller.read,cloud_controller_service_permissions.read,openid,password.write", "password,authorization_code,refresh_token",
                "uaa.resource");
        clientDetails.setClientSecret("appclientsecret");
        createClient(client, testAccounts.getClientDetails("oauth.clients.app", clientDetails));
    }

    private void createClient(RestOperations client, ClientDetails clientDetails) {
        ResponseEntity<String> response = client.postForEntity(serverRunning.getClientsUri(), clientDetails,
                String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    }

    private boolean clientExists(RestOperations client, OAuth2ProtectedResourceDetails resource) {
        ResponseEntity<String> response = client.getForEntity(
                serverRunning.getClientsUri() + "/" + resource.getClientId(), String.class);
        return response != null && response.getStatusCode() == HttpStatus.OK;
    }

    private boolean cfClientExists(RestOperations client) {
        return clientExists(client, testAccounts.getImplicitResource("oauth.clients.cf", "cf", null));
    }

    private boolean scimClientExists(RestOperations client) {
        return clientExists(client,
                testAccounts.getClientCredentialsResource("oauth.clients.scim", "scim", "scimsecret"));
    }

    private boolean appClientExists(RestOperations client) {
        return clientExists(client,
                testAccounts.getClientCredentialsResource("oauth.clients.app", "app", "appclientsecret"));
    }

    private void initializeUserAccount(RestOperations client) {
        if (this.user == null) {
            UaaUser user = testAccounts.getUserWithRandomID();
            @SuppressWarnings("rawtypes")
            ResponseEntity<Map> results = client.getForEntity(serverRunning.getUserUri() + "?filter=userName eq \""
                    + user.getUsername() + "\"", Map.class);
            assertThat(results.getStatusCode()).isEqualTo(HttpStatus.OK);
            @SuppressWarnings("unchecked")
            List<Map<String, ?>> resources = (List<Map<String, ?>>) results.getBody().get("resources");
            Map<String, ?> map;
            if (!resources.isEmpty()) {
                map = resources.getFirst();
            } else {
                map = getUserAsMap(user);
                @SuppressWarnings("rawtypes")
                ResponseEntity<Map> response = client.postForEntity(serverRunning.getUserUri(), map, Map.class);
                Assert.state(response.getStatusCode() == HttpStatus.CREATED, "User account not created: status was "
                        + response.getStatusCode());
                @SuppressWarnings("unchecked")
                Map<String, ?> value = response.getBody();
                map = value;
            }
            this.user = getUserFromMap(map);
        }
    }

    private UaaUser getUserFromMap(Map<String, ?> map) {
        String id = (String) map.get("id");
        String userName = (String) map.get("userName");
        String email = null;
        if (map.containsKey("emails")) {
            @SuppressWarnings("unchecked")
            Collection<Map<String, String>> emails = (Collection<Map<String, String>>) map.get("emails");
            if (!emails.isEmpty()) {
                email = emails.iterator().next().get("value");
            }
        }
        String givenName = null;
        String familyName = null;
        if (map.containsKey("name")) {
            @SuppressWarnings("unchecked")
            Map<String, String> name = (Map<String, String>) map.get("name");
            givenName = name.get("givenName");
            familyName = name.get("familyName");
        }
        @SuppressWarnings("unchecked")
        Collection<Map<String, String>> groups = (Collection<Map<String, String>>) map.get("groups");
        return new UaaUser(id, userName, "<N/A>", email, extractAuthorities(groups), givenName, familyName, new Date(),
                new Date(), OriginKeys.UAA, "externalId", false, IdentityZoneHolder.get().getId(), null, null);
    }

    private List<? extends GrantedAuthority> extractAuthorities(Collection<Map<String, String>> groups) {
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        for (Map<String, String> group : groups) {
            String role = group.get("display");
            Assert.state(role != null, "Role is null in this group: " + group);
            authorities.add(new SimpleGrantedAuthority(role));
        }
        return authorities;
    }

    private Map<String, ?> getUserAsMap(UaaUser user) {
        HashMap<String, Object> result = new HashMap<>();
        if (user.getId() != null) {
            result.put("id", user.getId());
        }
        if (user.getUsername() != null) {
            result.put("userName", user.getUsername());
        }
        if (user.getPassword() != null) {
            result.put("password", user.getPassword());
        } else {
            result.put("password", "password");
        }
        String email = user.getEmail();
        if (email != null) {
            @SuppressWarnings("unchecked")
            List<Map<String, String>> emails = Collections.singletonList(Collections.singletonMap("value", email));
            result.put("emails", emails);
        }
        String givenName = user.getGivenName();
        if (givenName != null) {
            Map<String, String> name = new HashMap<>();
            name.put("givenName", givenName);
            if (user.getFamilyName() != null) {
                name.put("familyName", user.getFamilyName());
            }
            result.put("name", name);
        }
        return result;
    }

    private OAuth2RestTemplate createRestTemplate(OAuth2ProtectedResourceDetails resource,
                                                  AccessTokenRequest accessTokenRequest) {
        OAuth2ClientContext context = new DefaultOAuth2ClientContext(accessTokenRequest);
        OAuth2RestTemplate client = new OAuth2RestTemplate(resource, context);
        client.setRequestFactory(new SimpleClientHttpRequestFactory() {
            @Override
            protected void prepareConnection(HttpURLConnection connection, String httpMethod) throws IOException {
                super.prepareConnection(connection, httpMethod);
                connection.setInstanceFollowRedirects(false);
            }
        });
        client.setErrorHandler(new OAuth2ErrorHandler(client.getResource()) {
            // Pass errors through in response entity for status code analysis
            @Override
            public boolean hasError(ClientHttpResponse response) {
                return false;
            }

            @Override
            public void handleError(ClientHttpResponse response) {
                // do nothing
            }
        });
        List<HttpMessageConverter<?>> list = new ArrayList<>();
        list.add(new StringHttpMessageConverter());
        list.add(new MappingJackson2HttpMessageConverter());
        client.setMessageConverters(list);
        return client;
    }
}
