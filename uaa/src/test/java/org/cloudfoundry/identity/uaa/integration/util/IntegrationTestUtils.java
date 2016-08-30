/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.integration.util;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.io.FileUtils;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.AbstractXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.XOIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.resources.SearchResults;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.junit.Assert;
import org.openqa.selenium.OutputType;
import org.openqa.selenium.TakesScreenshot;
import org.openqa.selenium.WebDriver;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.http.OAuth2ErrorHandler;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

import java.io.File;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.URI;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.USER_OAUTH_APPROVAL;

public class IntegrationTestUtils {

    public static final DefaultResponseErrorHandler fiveHundredErrorHandler = new DefaultResponseErrorHandler(){
        @Override
        protected boolean hasError(HttpStatus statusCode) {
            return statusCode.is5xxServerError();
        }
    };

    public static boolean doesSupportZoneDNS() {
        try {
            return Arrays.equals(Inet4Address.getByName("testzone1.localhost").getAddress(), new byte[] {127,0,0,1}) &&
                Arrays.equals(Inet4Address.getByName("testzone2.localhost").getAddress(), new byte[] {127,0,0,1}) &&
                Arrays.equals(Inet4Address.getByName("testzone3.localhost").getAddress(), new byte[] {127,0,0,1}) &&
                Arrays.equals(Inet4Address.getByName("testzone4.localhost").getAddress(), new byte[] {127,0,0,1}) &&
                Arrays.equals(Inet4Address.getByName("testzonedoesnotexist.localhost").getAddress(), new byte[] {127,0,0,1});
        } catch (UnknownHostException e) {
            return false;
        }
    }

    public static ClientCredentialsResourceDetails getClientCredentialsResource(String url,
                                                                                String[] scope,
                                                                                String clientId,
                                                                                String clientSecret) {
        ClientCredentialsResourceDetails resource = new ClientCredentialsResourceDetails();
        resource.setClientId(clientId);
        resource.setClientSecret(clientSecret);
        resource.setId(clientId);
        if (scope != null) {
            resource.setScope(Arrays.asList(scope));
        }
        resource.setClientAuthenticationScheme(AuthenticationScheme.header);
        resource.setAccessTokenUri(url + "/oauth/token");
        return resource;
    }

    public static RestTemplate getClientCredentialsTemplate(ClientCredentialsResourceDetails details) {
        RestTemplate client = new OAuth2RestTemplate(details);
        client.setRequestFactory(new StatelessRequestFactory());
        client.setErrorHandler(new OAuth2ErrorHandler(details) {
            // Pass errors through in response entity for status code analysis
            @Override
            public boolean hasError(ClientHttpResponse response) throws IOException {
                return false;
            }

            @Override
            public void handleError(ClientHttpResponse response) throws IOException {
            }
        });
        return client;
    }

    public static ScimUser createUser(RestTemplate client,
                                      String url,
                                      String username,
                                      String firstName,
                                      String lastName,
                                      String email,
                                      boolean verified) {

        ScimUser user = new ScimUser();
        user.setUserName(username);
        user.setName(new ScimUser.Name(firstName, lastName));
        user.addEmail(email);
        user.setVerified(verified);
        user.setActive(true);
        user.setPassword("secr3T");
        return client.postForEntity(url+"/Users", user, ScimUser.class).getBody();
    }

    public static ScimUser updateUser(String token, String url, ScimUser user) {
        RestTemplate template = new RestTemplate();
        MultiValueMap<String,String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + token);
        headers.add("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        headers.add("If-Match", String.valueOf(user.getVersion()));
        HttpEntity getHeaders = new HttpEntity(user,headers);
        ResponseEntity<ScimUser> userInfoGet = template.exchange(
            url+"/Users/"+user.getId(),
            HttpMethod.PUT,
            getHeaders,
            ScimUser.class
        );
        if (userInfoGet.getStatusCode() == HttpStatus.OK) {
            return userInfoGet.getBody();
        }
        throw new RuntimeException("Invalid return code:"+userInfoGet.getStatusCode());
    }

    public static ScimUser getUser(String token, String url, String origin, String username) {
        String userId = getUserId(token, url, origin, username);
        return getUser(token, url, userId);
    }

    public static ScimUser getUser(String token, String url, String userId) {
        RestTemplate template = new RestTemplate();
        MultiValueMap<String,String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + token);
        headers.add("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        HttpEntity getHeaders = new HttpEntity(headers);
        ResponseEntity<ScimUser> userInfoGet = template.exchange(
            url+"/Users/"+userId,
            HttpMethod.GET,
            getHeaders,
            ScimUser.class
        );
        if (userInfoGet.getStatusCode() == HttpStatus.OK) {
            return userInfoGet.getBody();
        }
        throw new RuntimeException("Invalid return code:"+userInfoGet.getStatusCode());
    }

    public static String getUserId(String token, String url, String origin, String username) {
        return getUserIdByField(token, url, origin, "userName", username);
    }
    public static String getUserIdByField(String token, String url, String origin, String field, String fieldValue) {
        RestTemplate template = new RestTemplate();
        MultiValueMap<String,String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + token);
        headers.add("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        HttpEntity getHeaders = new HttpEntity(headers);
        ResponseEntity<String> userInfoGet = template.exchange(
                url+"/Users"
                        + "?attributes=id"
                        + "&filter="+field+" eq \"" + fieldValue + "\" and origin eq \"" + origin +"\"",
                HttpMethod.GET,
                getHeaders,
                String.class
        );
        if (userInfoGet.getStatusCode() == HttpStatus.OK) {

            HashMap results = JsonUtils.readValue(userInfoGet.getBody(), HashMap.class);
            List resources = (List) results.get("resources");
            if (resources.size() < 1) {
                return null;
            }
            HashMap resource = (HashMap)resources.get(0);
            return (String) resource.get("id");
        }
        throw new RuntimeException("Invalid return code:"+userInfoGet.getStatusCode());
    }

    public static String getUsernameById(String token, String url, String userId) {
        return getUser(token, url, userId).getUserName();
    }

    public static void deleteUser(String zoneAdminToken, String url, String userId) {

        RestTemplate template = new RestTemplate();
        MultiValueMap<String,String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + zoneAdminToken);
        headers.add("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        HttpEntity deleteHeaders = new HttpEntity(headers);
        ResponseEntity<String> userDelete = template.exchange(
            url + "/Users/" + userId,
            HttpMethod.DELETE,
            deleteHeaders,
            String.class
        );
        if (userDelete.getStatusCode() != HttpStatus.OK) {
            throw new RuntimeException("Invalid return code:"+userDelete.getStatusCode());
        }
    }

    @SuppressWarnings("rawtypes")
    public static Map findAllGroups(RestTemplate client,
                                    String url) {
        ResponseEntity<Map> response = client.getForEntity(url + "/Groups", Map.class);

        @SuppressWarnings("rawtypes")
        Map results = response.getBody();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue("There should be more than zero groups", (Integer) results.get("totalResults") > 0);
        return results;
    }

    public static String findGroupId(RestTemplate client,
                                     String url,
                                     String groupName) {
        //TODO - make more efficient query using filter "id eq \"value\""
        Map map = findAllGroups(client, url);
        for (Map group : ((List<Map>)map.get("resources"))) {
            assertTrue(group.containsKey("displayName"));
            assertTrue(group.containsKey("id"));
            if (groupName.equals(group.get("displayName"))) {
                return (String)group.get("id");
            }
        }
        return null;
    }

    public static ScimGroup getGroup(RestTemplate client,
                                     String url,
                                     String groupName) {
        String id = findGroupId(client, url, groupName);
        if (id!=null) {
            ResponseEntity<ScimGroup> group = client.getForEntity(url + "/Groups/{id}", ScimGroup.class, id);
            return group.getBody();
        }
        return null;
    }

    public static ScimGroup createOrUpdateGroup(RestTemplate client,
                                                String url,
                                                ScimGroup scimGroup) {
        //dont modify the actual argument
        LinkedList<ScimGroupMember> members = new LinkedList<>(scimGroup.getMembers());
        ScimGroup existing = getGroup(client, url, scimGroup.getDisplayName());
        if (existing!=null) {
            members.addAll(existing.getMembers());
        }
        scimGroup.setMembers(members);
        if (existing!=null) {
            scimGroup.setId(existing.getId());
            client.put(url + "/Groups/{id}", scimGroup, scimGroup.getId());
            return scimGroup;
        } else {
            ResponseEntity<String> group = client.postForEntity(url + "/Groups", scimGroup, String.class);
            if (group.getStatusCode()==HttpStatus.CREATED) {
                return JsonUtils.readValue(group.getBody(), ScimGroup.class);
            } else {
                throw new IllegalStateException("Invalid return code:"+group.getStatusCode());
            }
        }
    }

    public static ScimGroup getGroup(String token,
                                     String zoneId,
                                     String url,
                                     String displayName) {
        RestTemplate template = new RestTemplate();
        MultiValueMap<String,String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + token);
        headers.add("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        if (StringUtils.hasText(zoneId)) {
            headers.add(IdentityZoneSwitchingFilter.HEADER, zoneId);
        }
        ResponseEntity<SearchResults<ScimGroup>> findGroup = template.exchange(
            url + "/Groups?filter=displayName eq \"{groupId}\"",
            HttpMethod.GET,
            new HttpEntity(headers),
            new ParameterizedTypeReference<SearchResults<ScimGroup>>() {},
            displayName
        );
        if (findGroup.getBody().getTotalResults()==0) {
            return null;
        } else {
            return findGroup.getBody().getResources().iterator().next();
        }
    }

    public static ScimGroup createGroup(String token,
                                        String zoneId,
                                        String url,
                                        ScimGroup group) {
        RestTemplate template = new RestTemplate();
        template.setErrorHandler(fiveHundredErrorHandler);
        MultiValueMap<String,String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + token);
        headers.add("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        if (StringUtils.hasText(zoneId)) {
            headers.add(IdentityZoneSwitchingFilter.HEADER, zoneId);
        }
        ResponseEntity<ScimGroup> createGroup = template.exchange(
            url + "/Groups",
            HttpMethod.POST,
            new HttpEntity(JsonUtils.writeValueAsBytes(group),headers),
            ScimGroup.class
        );
        assertEquals(HttpStatus.CREATED, createGroup.getStatusCode());
        return createGroup.getBody();
    }

    public static ScimGroup updateGroup(String token,
                                        String zoneId,
                                        String url,
                                        ScimGroup group) {
        RestTemplate template = new RestTemplate();
        MultiValueMap<String,String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + token);
        headers.add("If-Match", "*");
        headers.add("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        if (StringUtils.hasText(zoneId)) {
            headers.add(IdentityZoneSwitchingFilter.HEADER, zoneId);
        }
        ResponseEntity<ScimGroup> updateGroup = template.exchange(
            url + "/Groups/{groupId}",
            HttpMethod.PUT,
            new HttpEntity(JsonUtils.writeValueAsBytes(group),headers),
            ScimGroup.class,
            group.getId()
        );
        assertEquals(HttpStatus.OK, updateGroup.getStatusCode());
        return updateGroup.getBody();
    }

    public static ScimGroup createOrUpdateGroup(String token,
                                                String zoneId,
                                                String url,
                                                ScimGroup scimGroup) {

        ScimGroup existing = getGroup(token, zoneId, url, scimGroup.getDisplayName());
        if (existing==null) {
            return createGroup(token, zoneId, url, scimGroup);
        } else {
            scimGroup.setId(existing.getId());
            return updateGroup(token, zoneId, url, scimGroup);
        }

    }

    public static ScimGroupExternalMember mapExternalGroup(String token,
                                                           String zoneId,
                                                           String url,
                                                           ScimGroupExternalMember scimGroup) {

        RestTemplate template = new RestTemplate();
        MultiValueMap<String,String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + token);
        headers.add("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        if (StringUtils.hasText(zoneId)) {
            headers.add(IdentityZoneSwitchingFilter.HEADER, zoneId);
        }
        ResponseEntity<ScimGroupExternalMember> mapGroup = template.exchange(
            url + "/Groups/External",
            HttpMethod.POST,
            new HttpEntity(JsonUtils.writeValueAsBytes(scimGroup), headers),
            ScimGroupExternalMember.class
        );
        if (HttpStatus.CREATED.equals(mapGroup.getStatusCode())) {
            return mapGroup.getBody();
        } else if (HttpStatus.CONFLICT.equals(mapGroup.getStatusCode())) {
            return scimGroup;
        }
        throw new IllegalArgumentException("Invalid status code:"+mapGroup.getStatusCode());
    }

    public static IdentityZone createZoneOrUpdateSubdomain(RestTemplate client,
                                                           String url,
                                                           String id,
                                                           String subdomain) {
        return createZoneOrUpdateSubdomain(client, url, id, subdomain, x -> {});
    }

    public static IdentityZone createZoneOrUpdateSubdomain(RestTemplate client,
                                                           String url,
                                                           String id,
                                                           String subdomain,
                                                           Consumer<IdentityZoneConfiguration> configureZone) {

        ResponseEntity<String> zoneGet = client.getForEntity(url + "/identity-zones/{id}", String.class, id);
        if (zoneGet.getStatusCode()==HttpStatus.OK) {
            IdentityZone existing = JsonUtils.readValue(zoneGet.getBody(), IdentityZone.class);
            existing.setSubdomain(subdomain);
            client.put(url + "/identity-zones/{id}", existing, id);
            return existing;
        }
        IdentityZone identityZone = fixtureIdentityZone(id, subdomain, new IdentityZoneConfiguration());
        configureZone.accept(identityZone.getConfig());

        ResponseEntity<IdentityZone> zone = client.postForEntity(url + "/identity-zones", identityZone, IdentityZone.class);
        return zone.getBody();
    }

    public static IdentityZone createZoneOrUpdateSubdomain(RestTemplate client,
            String url,
            String id,
            String subdomain,
            IdentityZoneConfiguration config) {

        ResponseEntity<String> zoneGet = client.getForEntity(url + "/identity-zones/{id}", String.class, id);
        if (zoneGet.getStatusCode()==HttpStatus.OK) {
        IdentityZone existing = JsonUtils.readValue(zoneGet.getBody(), IdentityZone.class);
        existing.setSubdomain(subdomain);
        existing.setConfig(config);
        client.put(url + "/identity-zones/{id}", existing, id);
        return existing;
        }
        IdentityZone identityZone = fixtureIdentityZone(id, subdomain, config);
        ResponseEntity<IdentityZone> zone = client.postForEntity(url + "/identity-zones", identityZone, IdentityZone.class);
        return zone.getBody();
    }

    public static void makeZoneAdmin(RestTemplate client,
                                     String url,
                                     String userId,
                                     String zoneId) {
        ScimGroupMember member = new ScimGroupMember(userId);
        String groupName = "zones."+zoneId+".admin";
        ScimGroup group = new ScimGroup(null,groupName,zoneId);
        group.setMembers(Arrays.asList(member));
        ResponseEntity<String> response = client.postForEntity(url + "/Groups/zones", group, String.class);
        assertEquals(HttpStatus.CREATED, response.getStatusCode());
    }

    public static BaseClientDetails getClient(RestTemplate template,
                                              String url,
                                              String clientId) throws Exception {
        ResponseEntity<BaseClientDetails> response = template.getForEntity(url+"/oauth/clients/{clientId}", BaseClientDetails.class, clientId);
        return response.getBody();
    }

    public static BaseClientDetails createClientAsZoneAdmin(String zoneAdminToken,
                                                            String url,
                                                            String zoneId,
                                                            BaseClientDetails client) throws Exception {

        RestTemplate template = new RestTemplate();
        MultiValueMap<String,String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer "+zoneAdminToken);
        headers.add("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        headers.add(IdentityZoneSwitchingFilter.HEADER, zoneId);
        HttpEntity getHeaders = new HttpEntity(JsonUtils.writeValueAsBytes(client), headers);
        ResponseEntity<String> clientCreate = template.exchange(
            url + "/oauth/clients",
            HttpMethod.POST,
            getHeaders,
            String.class
        );
        if (clientCreate.getStatusCode() == HttpStatus.CREATED) {
            return JsonUtils.readValue(clientCreate.getBody(), BaseClientDetails.class);
        }
        throw new RuntimeException("Invalid return code:"+clientCreate.getStatusCode());
    }

    public static BaseClientDetails createClient(String adminToken,
                                                 String url,
                                                 BaseClientDetails client) throws Exception {
        return createOrUpdateClient(adminToken, url, null, client);
    }
    public static BaseClientDetails createOrUpdateClient(String adminToken,
                                                         String url,
                                                         String switchToZoneId,
                                                         BaseClientDetails client) throws Exception {

        RestTemplate template = new RestTemplate();
        template.setErrorHandler(new DefaultResponseErrorHandler() {
            @Override
            protected boolean hasError(HttpStatus statusCode) {
                return statusCode.is5xxServerError();
            }
        });
        MultiValueMap<String,String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer "+ adminToken);
        headers.add("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        if (StringUtils.hasText(switchToZoneId)) {
            headers.add(IdentityZoneSwitchingFilter.HEADER, switchToZoneId);
        }
        HttpEntity getHeaders = new HttpEntity(JsonUtils.writeValueAsBytes(client), headers);
        ResponseEntity<String> clientCreate = template.exchange(
                url + "/oauth/clients",
                HttpMethod.POST,
                getHeaders,
                String.class
        );
        if (clientCreate.getStatusCode() == HttpStatus.CREATED) {
            return JsonUtils.readValue(clientCreate.getBody(), BaseClientDetails.class);
        } else if (clientCreate.getStatusCode() == HttpStatus.CONFLICT) {
            HttpEntity putHeaders = new HttpEntity(JsonUtils.writeValueAsBytes(client), headers);
            ResponseEntity<String> clientUpdate = template.exchange(
                url + "/oauth/clients/"+client.getClientId(),
                HttpMethod.PUT,
                putHeaders,
                String.class
            );
            if (clientUpdate.getStatusCode() == HttpStatus.OK) {
                return JsonUtils.readValue(clientCreate.getBody(), BaseClientDetails.class);
            } else {
                throw new RuntimeException("Invalid update return code:"+clientUpdate.getStatusCode());
            }
        }
        throw new RuntimeException("Invalid crete return code:"+clientCreate.getStatusCode());
    }

    public static BaseClientDetails updateClient(RestTemplate template,
                                                 String url,
                                                 BaseClientDetails client) throws Exception {

        ResponseEntity<BaseClientDetails> response = template.exchange(
            url + "/oauth/clients/{clientId}",
            HttpMethod.PUT,
            new HttpEntity<>(client),
            BaseClientDetails.class,
            client.getClientId());

        return response.getBody();
    }

    public static IdentityProvider getProvider(String zoneAdminToken,
                                               String url,
                                               String zoneId,
                                               String originKey) {
        List<IdentityProvider> providers = getProviders(zoneAdminToken, url, zoneId);
        if (providers!=null) {
            for (IdentityProvider p : providers) {
                if (zoneId.equals(p.getIdentityZoneId()) && originKey.equals(p.getOriginKey())) {
                    return p;
                }
            }
        }
        return null;
    }

    public static List<IdentityProvider> getProviders(String zoneAdminToken,
                                                      String url,
                                                      String zoneId) {
        RestTemplate client = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + zoneAdminToken);
        headers.add("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        headers.add(IdentityZoneSwitchingFilter.HEADER, zoneId);
        HttpEntity getHeaders = new HttpEntity(headers);
        ResponseEntity<String> providerGet = client.exchange(
            url + "/identity-providers",
            HttpMethod.GET,
            getHeaders,
            String.class
        );
        if (providerGet != null && providerGet.getStatusCode() == HttpStatus.OK) {
            return JsonUtils.readValue(providerGet.getBody(), new TypeReference<List<IdentityProvider>>() {
            });
        }
        return null;
    }

    public static void deleteProvider(String zoneAdminToken,
                                      String url,
                                      String zoneId,
                                      String originKey) {
        IdentityProvider provider = getProvider(zoneAdminToken, url, zoneId, originKey);
        RestTemplate client = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Authorization", "bearer " + zoneAdminToken);
        headers.add(IdentityZoneSwitchingFilter.HEADER, zoneId);
        HttpEntity getHeaders = new HttpEntity(headers);
        client.exchange(
            url + "/identity-providers/" + provider.getId(),
            HttpMethod.DELETE,
            getHeaders,
            String.class
        );
    }

    /**
     * @param originKey The unique identifier used to reference the identity provider in UAA.
     * @param addShadowUserOnLogin Specifies whether UAA should automatically create shadow users upon successful SAML authentication.
     * @return An object representation of an identity provider.
     * @throws Exception on error
     */
    public static IdentityProvider createIdentityProvider(String originKey, boolean addShadowUserOnLogin, String baseUrl, ServerRunning serverRunning) throws Exception {
        String zoneAdminToken = getZoneAdminToken(baseUrl, serverRunning);
        SamlIdentityProviderDefinition samlIdentityProviderDefinition = createSimplePHPSamlIDP(originKey, OriginKeys.UAA);
        return createIdentityProvider("simplesamlphp for uaa", originKey, addShadowUserOnLogin, baseUrl, serverRunning, samlIdentityProviderDefinition);
    }

    /**
     * @param originKey The unique identifier used to reference the identity provider in UAA.
     * @param addShadowUserOnLogin Specifies whether UAA should automatically create shadow users upon successful SAML authentication.
     * @return An object representation of an identity provider.
     * @throws Exception on error
     */
    public static IdentityProvider createIdentityProvider(String name, String originKey, boolean addShadowUserOnLogin, String baseUrl, ServerRunning serverRunning, SamlIdentityProviderDefinition samlIdentityProviderDefinition) throws Exception {
        String zoneAdminToken = getZoneAdminToken(baseUrl, serverRunning);

        samlIdentityProviderDefinition.setAddShadowUserOnLogin(addShadowUserOnLogin);
        IdentityProvider provider = new IdentityProvider();
        provider.setIdentityZoneId(OriginKeys.UAA);
        provider.setType(OriginKeys.SAML);
        provider.setActive(true);
        provider.setConfig(samlIdentityProviderDefinition);
        provider.setOriginKey(samlIdentityProviderDefinition.getIdpEntityAlias());
        provider.setName(name);
        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken,baseUrl,provider);
        assertNotNull(provider.getId());
        return provider;
    }

    public static IdentityProvider createOidcIdentityProvider(String name, String originKey, String baseUrl) throws Exception {
        IdentityProvider<AbstractXOAuthIdentityProviderDefinition> identityProvider = new IdentityProvider<>();
        identityProvider.setName(name);
        identityProvider.setIdentityZoneId(OriginKeys.UAA);
        XOIDCIdentityProviderDefinition config = new XOIDCIdentityProviderDefinition();
        config.addAttributeMapping(USER_NAME_ATTRIBUTE_NAME, "user_name");
        config.setAuthUrl(new URL("https://oidc10.identity.cf-app.com/oauth/authorize"));
        config.setTokenUrl(new URL("https://oidc10.identity.cf-app.com/oauth/token"));
        config.setTokenKeyUrl(new URL("https://oidc10.identity.cf-app.com/token_key"));
        config.setShowLinkText(true);
        config.setLinkText("My OIDC Provider");
        config.setSkipSslValidation(true);
        config.setRelyingPartyId("identity");
        config.setRelyingPartySecret("identitysecret");
        config.setEmailDomain(Collections.singletonList("test.org"));
        identityProvider.setConfig(config);
        identityProvider.setOriginKey(originKey);
        String clientCredentialsToken = IntegrationTestUtils.getClientCredentialsToken(baseUrl, "admin", "adminsecret");
        IntegrationTestUtils.createOrUpdateProvider(clientCredentialsToken, baseUrl, identityProvider);
        return identityProvider;
    }

    public static String getZoneAdminToken(String baseUrl, ServerRunning serverRunning) throws Exception {
        RestTemplate identityClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "identity", "identitysecret")
        );
        RestTemplate adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "admin", "adminsecret")
        );
        String email = new RandomValueStringGenerator().generate() +"@samltesting.org";
        ScimUser user = IntegrationTestUtils.createUser(adminClient, baseUrl, email, "firstname", "lastname", email, true);
        IntegrationTestUtils.makeZoneAdmin(identityClient, baseUrl, user.getId(), OriginKeys.UAA);

        return IntegrationTestUtils.getAuthorizationCodeToken(serverRunning,
            UaaTestAccounts.standard(serverRunning),
            "identity",
            "identitysecret",
            email,
            "secr3T");
    }

    public static ScimUser createRandomUser(String baseUrl) throws Exception {

        RestTemplate adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "admin", "adminsecret")
        );
        String email = new RandomValueStringGenerator().generate() +"@samltesting.org";
        return IntegrationTestUtils.createUser(adminClient, baseUrl, email, "firstname", "lastname", email, true);
    }

    public static IdentityProvider updateIdentityProvider(
            String baseUrl, ServerRunning serverRunning, IdentityProvider provider) throws Exception {
        RestTemplate identityClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "identity", "identitysecret")
        );
        RestTemplate adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "admin", "adminsecret")
        );
        String email = new RandomValueStringGenerator().generate() +"@samltesting.org";
        ScimUser user = IntegrationTestUtils.createUser(adminClient, baseUrl, email, "firstname", "lastname", email, true);
        IntegrationTestUtils.makeZoneAdmin(identityClient, baseUrl, user.getId(), OriginKeys.UAA);

        String zoneAdminToken =
            IntegrationTestUtils.getAuthorizationCodeToken(serverRunning,
                UaaTestAccounts.standard(serverRunning),
                "identity",
                "identitysecret",
                email,
                "secr3T");

        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken, baseUrl, provider);
        assertNotNull(provider.getId());
        return provider;
    }

    public static SamlIdentityProviderDefinition createSimplePHPSamlIDP(String alias, String zoneId) {
        if (!("simplesamlphp".equals(alias) || "simplesamlphp2".equals(alias))) {
            throw new IllegalArgumentException("Only valid origins are: simplesamlphp,simplesamlphp2");
        }
        String idpMetaData = "<?xml version=\"1.0\"?>\n" +
            "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" entityID=\"http://"+alias+".cfapps.io/saml2/idp/metadata.php\" ID=\"pfx06ad4153-c17c-d286-194c-dec30bb92796\"><ds:Signature>\n" +
            "  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
            "    <ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n" +
            "  <ds:Reference URI=\"#pfx06ad4153-c17c-d286-194c-dec30bb92796\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>begl1WVCsXSn7iHixtWPP8d/X+k=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>BmbKqA3A0oSLcn5jImz/l5WbpVXj+8JIpT/ENWjOjSd/gcAsZm1QvYg+RxYPBk+iV2bBxD+/yAE/w0wibsHrl0u9eDhoMRUJBUSmeyuN1lYzBuoVa08PdAGtb5cGm4DMQT5Rzakb1P0hhEPPEDDHgTTxop89LUu6xx97t2Q03Khy8mXEmBmNt2NlFxJPNt0FwHqLKOHRKBOE/+BpswlBocjOQKFsI9tG3TyjFC68mM2jo0fpUQCgj5ZfhzolvS7z7c6V201d9Tqig0/mMFFJLTN8WuZPavw22AJlMjsDY9my+4R9HKhK5U53DhcTeECs9fb4gd7p5BJy4vVp7tqqOg==</ds:SignatureValue>\n" +
            "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIEEzCCAvugAwIBAgIJAIc1qzLrv+5nMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ08xFDASBgNVBAcMC0Nhc3RsZSBSb2NrMRwwGgYDVQQKDBNTYW1sIFRlc3RpbmcgU2VydmVyMQswCQYDVQQLDAJJVDEgMB4GA1UEAwwXc2ltcGxlc2FtbHBocC5jZmFwcHMuaW8xIDAeBgkqhkiG9w0BCQEWEWZoYW5pa0BwaXZvdGFsLmlvMB4XDTE1MDIyMzIyNDUwM1oXDTI1MDIyMjIyNDUwM1owgZ8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDTzEUMBIGA1UEBwwLQ2FzdGxlIFJvY2sxHDAaBgNVBAoME1NhbWwgVGVzdGluZyBTZXJ2ZXIxCzAJBgNVBAsMAklUMSAwHgYDVQQDDBdzaW1wbGVzYW1scGhwLmNmYXBwcy5pbzEgMB4GCSqGSIb3DQEJARYRZmhhbmlrQHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4cn62E1xLqpN34PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz2ZivLwZXW+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWWRDodcoHEfDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQnX8Ttl7hZ6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5cljz0X/TXy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gphiJH3jvZ7I+J5lS8VAgMBAAGjUDBOMB0GA1UdDgQWBBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAfBgNVHSMEGDAWgBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAvMS4EQeP/ipV4jOG5lO6/tYCb/iJeAduOnRhkJk0DbX329lDLZhTTL/x/w/9muCVcvLrzEp6PN+VWfw5E5FWtZN0yhGtP9R+vZnrV+oc2zGD+no1/ySFOe3EiJCO5dehxKjYEmBRv5sU/LZFKZpozKN/BMEa6CqLuxbzb7ykxVr7EVFXwltPxzE9TmL9OACNNyF5eJHWMRMllarUvkcXlh4pux4ks9e6zV9DQBy2zds9f1I3qxg0eX6JnGrXi/ZiCT+lJgVe3ZFXiejiLAiKB04sXW3ti0LW3lx13Y1YlQ4/tlpgTgfIJxKV6nyPiLoK0nywbMd+vpAirDt2Oc+hk</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>\n" +
            "  <md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n" +
            "    <md:KeyDescriptor use=\"signing\">\n" +
            "      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
            "        <ds:X509Data>\n" +
            "          <ds:X509Certificate>MIIEEzCCAvugAwIBAgIJAIc1qzLrv+5nMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ08xFDASBgNVBAcMC0Nhc3RsZSBSb2NrMRwwGgYDVQQKDBNTYW1sIFRlc3RpbmcgU2VydmVyMQswCQYDVQQLDAJJVDEgMB4GA1UEAwwXc2ltcGxlc2FtbHBocC5jZmFwcHMuaW8xIDAeBgkqhkiG9w0BCQEWEWZoYW5pa0BwaXZvdGFsLmlvMB4XDTE1MDIyMzIyNDUwM1oXDTI1MDIyMjIyNDUwM1owgZ8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDTzEUMBIGA1UEBwwLQ2FzdGxlIFJvY2sxHDAaBgNVBAoME1NhbWwgVGVzdGluZyBTZXJ2ZXIxCzAJBgNVBAsMAklUMSAwHgYDVQQDDBdzaW1wbGVzYW1scGhwLmNmYXBwcy5pbzEgMB4GCSqGSIb3DQEJARYRZmhhbmlrQHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4cn62E1xLqpN34PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz2ZivLwZXW+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWWRDodcoHEfDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQnX8Ttl7hZ6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5cljz0X/TXy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gphiJH3jvZ7I+J5lS8VAgMBAAGjUDBOMB0GA1UdDgQWBBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAfBgNVHSMEGDAWgBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAvMS4EQeP/ipV4jOG5lO6/tYCb/iJeAduOnRhkJk0DbX329lDLZhTTL/x/w/9muCVcvLrzEp6PN+VWfw5E5FWtZN0yhGtP9R+vZnrV+oc2zGD+no1/ySFOe3EiJCO5dehxKjYEmBRv5sU/LZFKZpozKN/BMEa6CqLuxbzb7ykxVr7EVFXwltPxzE9TmL9OACNNyF5eJHWMRMllarUvkcXlh4pux4ks9e6zV9DQBy2zds9f1I3qxg0eX6JnGrXi/ZiCT+lJgVe3ZFXiejiLAiKB04sXW3ti0LW3lx13Y1YlQ4/tlpgTgfIJxKV6nyPiLoK0nywbMd+vpAirDt2Oc+hk</ds:X509Certificate>\n" +
            "        </ds:X509Data>\n" +
            "      </ds:KeyInfo>\n" +
            "    </md:KeyDescriptor>\n" +
            "    <md:KeyDescriptor use=\"encryption\">\n" +
            "      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
            "        <ds:X509Data>\n" +
            "          <ds:X509Certificate>MIIEEzCCAvugAwIBAgIJAIc1qzLrv+5nMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ08xFDASBgNVBAcMC0Nhc3RsZSBSb2NrMRwwGgYDVQQKDBNTYW1sIFRlc3RpbmcgU2VydmVyMQswCQYDVQQLDAJJVDEgMB4GA1UEAwwXc2ltcGxlc2FtbHBocC5jZmFwcHMuaW8xIDAeBgkqhkiG9w0BCQEWEWZoYW5pa0BwaXZvdGFsLmlvMB4XDTE1MDIyMzIyNDUwM1oXDTI1MDIyMjIyNDUwM1owgZ8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDTzEUMBIGA1UEBwwLQ2FzdGxlIFJvY2sxHDAaBgNVBAoME1NhbWwgVGVzdGluZyBTZXJ2ZXIxCzAJBgNVBAsMAklUMSAwHgYDVQQDDBdzaW1wbGVzYW1scGhwLmNmYXBwcy5pbzEgMB4GCSqGSIb3DQEJARYRZmhhbmlrQHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4cn62E1xLqpN34PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz2ZivLwZXW+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWWRDodcoHEfDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQnX8Ttl7hZ6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5cljz0X/TXy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gphiJH3jvZ7I+J5lS8VAgMBAAGjUDBOMB0GA1UdDgQWBBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAfBgNVHSMEGDAWgBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAvMS4EQeP/ipV4jOG5lO6/tYCb/iJeAduOnRhkJk0DbX329lDLZhTTL/x/w/9muCVcvLrzEp6PN+VWfw5E5FWtZN0yhGtP9R+vZnrV+oc2zGD+no1/ySFOe3EiJCO5dehxKjYEmBRv5sU/LZFKZpozKN/BMEa6CqLuxbzb7ykxVr7EVFXwltPxzE9TmL9OACNNyF5eJHWMRMllarUvkcXlh4pux4ks9e6zV9DQBy2zds9f1I3qxg0eX6JnGrXi/ZiCT+lJgVe3ZFXiejiLAiKB04sXW3ti0LW3lx13Y1YlQ4/tlpgTgfIJxKV6nyPiLoK0nywbMd+vpAirDt2Oc+hk</ds:X509Certificate>\n" +
            "        </ds:X509Data>\n" +
            "      </ds:KeyInfo>\n" +
            "    </md:KeyDescriptor>\n" +
            "    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://"+alias+".cfapps.io/saml2/idp/SingleLogoutService.php\"/>\n" +
            "    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>\n" +
            "    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://"+alias+".cfapps.io/saml2/idp/SSOService.php\"/>\n" +
            "  </md:IDPSSODescriptor>\n" +
            "  <md:ContactPerson contactType=\"technical\">\n" +
            "    <md:GivenName>Filip</md:GivenName>\n" +
            "    <md:SurName>Hanik</md:SurName>\n" +
            "    <md:EmailAddress>fhanik@pivotal.io</md:EmailAddress>\n" +
            "  </md:ContactPerson>\n" +
            "</md:EntityDescriptor>";
        SamlIdentityProviderDefinition def = new SamlIdentityProviderDefinition();
        def.setZoneId(zoneId);
        def.setMetaDataLocation(idpMetaData);
        def.setNameID("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
        def.setAssertionConsumerIndex(0);
        def.setMetadataTrustCheck(false);
        def.setShowSamlLink(true);
        def.setIdpEntityAlias(alias);
        def.setLinkText("Login with Simple SAML PHP("+alias+")");
        return def;
    }

    public static IdentityProvider createOrUpdateProvider(String accessToken,
                                                          String url,
                                                          IdentityProvider provider) {
        RestTemplate client = new RestTemplate();
        MultiValueMap<String,String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer "+accessToken);
        headers.add("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        headers.add(IdentityZoneSwitchingFilter.HEADER, provider.getIdentityZoneId());
        List<IdentityProvider> existing = getProviders(accessToken, url, provider.getIdentityZoneId());
        if (existing!=null) {
            for (IdentityProvider p : existing) {
                if (p.getOriginKey().equals(provider.getOriginKey()) && p.getIdentityZoneId().equals(provider.getIdentityZoneId())) {
                    provider.setId(p.getId());
                    HttpEntity putHeaders = new HttpEntity(provider, headers);
                    ResponseEntity<String> providerPut = client.exchange(
                        url + "/identity-providers/{id}",
                        HttpMethod.PUT,
                        putHeaders,
                        String.class,
                        provider.getId()
                    );
                    if (providerPut.getStatusCode()==HttpStatus.OK) {
                        return JsonUtils.readValue(providerPut.getBody(), IdentityProvider.class);
                    }
                }
            }
        }

        HttpEntity postHeaders = new HttpEntity(provider, headers);
        ResponseEntity<String> providerPost = client.exchange(
            url + "/identity-providers/{id}",
            HttpMethod.POST,
            postHeaders,
            String.class,
            provider.getId()
        );
        if (providerPost.getStatusCode()==HttpStatus.CREATED) {
            return JsonUtils.readValue(providerPost.getBody(), IdentityProvider.class);
        }
        throw new IllegalStateException("Invalid result code returned, unable to create identity provider:"+providerPost.getStatusCode());
    }

    public static IdentityZone fixtureIdentityZone(String id, String subdomain) {

        return fixtureIdentityZone(id, subdomain, null);
    }

    public static IdentityZone fixtureIdentityZone(String id, String subdomain, IdentityZoneConfiguration config) {
        IdentityZone identityZone = new IdentityZone();
        identityZone.setId(id);
        identityZone.setSubdomain(subdomain);
        identityZone.setName("The Twiglet Zone[" + id + "]");
        identityZone.setDescription("Like the Twilight Zone but tastier[" + id + "].");
        identityZone.setConfig(config);
        return identityZone;
    }

    public static String getClientCredentialsToken(String baseUrl,
                                                   String clientId,
                                                   String clientSecret) throws Exception {
        RestTemplate template = new RestTemplate();
        template.setRequestFactory(new StatelessRequestFactory());
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", "client_credentials");
        formData.add("client_id", clientId);
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.set("Authorization", "Basic " + new String(Base64.encode(String.format("%s:%s", clientId, clientSecret).getBytes())));

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = template.exchange(
            baseUrl + "/oauth/token",
            HttpMethod.POST,
            new HttpEntity(formData, headers),
            Map.class);

        Assert.assertEquals(HttpStatus.OK, response.getStatusCode());

        @SuppressWarnings("unchecked")
        OAuth2AccessToken accessToken = DefaultOAuth2AccessToken.valueOf(response.getBody());
        return accessToken.getValue();
    }

    public static Map<String,Object> getPasswordToken(String baseUrl,
                                                      String clientId,
                                                      String clientSecret,
                                                      String username,
                                                      String password,
                                                      String scopes) throws Exception {
        RestTemplate template = new RestTemplate();
        template.getMessageConverters().add(0, new StringHttpMessageConverter(java.nio.charset.Charset.forName("UTF-8")));
        template.setRequestFactory(new StatelessRequestFactory());
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", "password");
        formData.add("client_id", clientId);
        formData.add("username", username);
        formData.add("password", password);
        formData.add("response_type", "token id_token");
        if (StringUtils.hasText(scopes)) {
            formData.add("scope", scopes);
        }
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.set("Authorization", "Basic " + new String(Base64.encode(String.format("%s:%s", clientId, clientSecret).getBytes())));

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = template.exchange(
            baseUrl + "/oauth/token",
            HttpMethod.POST,
            new HttpEntity(formData, headers),
            Map.class);

        Assert.assertEquals(HttpStatus.OK, response.getStatusCode());
        return response.getBody();
    }

    public static String getClientCredentialsToken(ServerRunning serverRunning,
                                                   String clientId,
                                                   String clientSecret) throws Exception {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add("grant_type", "client_credentials");
        formData.add("client_id", clientId);
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
        headers.set("Authorization",
            "Basic " + new String(Base64.encode(String.format("%s:%s", clientId, clientSecret).getBytes())));

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.postForMap("/oauth/token", formData, headers);
        Assert.assertEquals(HttpStatus.OK, response.getStatusCode());

        @SuppressWarnings("unchecked")
        OAuth2AccessToken accessToken = DefaultOAuth2AccessToken.valueOf(response.getBody());
        return accessToken.getValue();
    }

    public static String getAuthorizationCodeToken(ServerRunning serverRunning,
                                                   UaaTestAccounts testAccounts,
                                                   String clientId,
                                                   String clientSecret,
                                                   String username,
                                                   String password) throws Exception {

        return getAuthorizationCodeTokenMap(serverRunning, testAccounts, clientId, clientSecret, username, password)
            .get("access_token");
    }

    public static Map<String,String> getAuthorizationCodeTokenMap(ServerRunning serverRunning,
                                                                  UaaTestAccounts testAccounts,
                                                                  String clientId,
                                                                  String clientSecret,
                                                                  String username,
                                                                  String password) throws Exception {
        AuthorizationCodeResourceDetails resource = testAccounts.getDefaultAuthorizationCodeResource();
        resource.setClientId(clientId);
        resource.setClientSecret(clientSecret);

        return getAuthorizationCodeTokenMap(serverRunning,
                                            testAccounts,
                                            clientId,
                                            clientSecret,
                                            username,
                                            password,
                                            null,
                                            null,
                                            resource.getPreEstablishedRedirectUri(),
                                            true);
    }

    public static Map<String,String> getAuthorizationCodeTokenMap(ServerRunning serverRunning,
                                                                  UaaTestAccounts testAccounts,
                                                                  String clientId,
                                                                  String clientSecret,
                                                                  String username,
                                                                  String password,
                                                                  String tokenResponseType,
                                                                  String jSessionId,
                                                                  String redirectUri,
                                                                  boolean callCheckToken) throws Exception {
        // TODO Fix to use json API rather than HTML
        HttpHeaders headers = new HttpHeaders();
        if (StringUtils.hasText(jSessionId)) {
            headers.add("Cookie", "JSESSIONID="+jSessionId);
        }
        // TODO: should be able to handle just TEXT_HTML
        headers.setAccept(Arrays.asList(MediaType.TEXT_HTML, MediaType.ALL));

        String mystateid = "mystateid";
        ServerRunning.UriBuilder builder = serverRunning.buildUri("/oauth/authorize")
                .queryParam("response_type", "code")
                .queryParam("state", mystateid)
                .queryParam("client_id", clientId);
        if( StringUtils.hasText(redirectUri)) {
            builder = builder.queryParam("redirect_uri", redirectUri);
        }
        URI uri = builder.build();

        ResponseEntity<Void> result =
            serverRunning.createRestTemplate().exchange(
                uri.toString(),
                HttpMethod.GET,
                new HttpEntity<>(null,headers),
                Void.class
            );

        assertEquals(HttpStatus.FOUND, result.getStatusCode());
        String location = result.getHeaders().getLocation().toString();

        if (result.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : result.getHeaders().get("Set-Cookie")) {
                assertNotNull("Expected cookie in " + result.getHeaders(), cookie);
                headers.add("Cookie", cookie);
            }
        }

        ResponseEntity<String> response = serverRunning.getForString(location, headers);

        if (response.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : response.getHeaders().get("Set-Cookie")) {
                headers.add("Cookie", cookie);
            }
        }

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        if (!StringUtils.hasText(jSessionId)) {
            // should be directed to the login screen...
            assertTrue(response.getBody().contains("/login.do"));
            assertTrue(response.getBody().contains("username"));
            assertTrue(response.getBody().contains("password"));
            String csrf = IntegrationTestUtils.extractCookieCsrf(response.getBody());

            formData.add("username", username);
            formData.add("password", password);
            formData.add(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, csrf);

            // Should be redirected to the original URL, but now authenticated
            result = serverRunning.postForResponse("/login.do", headers, formData);
            assertEquals(HttpStatus.FOUND, result.getStatusCode());

            headers.remove("Cookie");
            if (result.getHeaders().containsKey("Set-Cookie")) {
                for (String cookie : result.getHeaders().get("Set-Cookie")) {
                    headers.add("Cookie", cookie);
                }
            }
        }

        response = serverRunning.createRestTemplate().exchange(
            result.getHeaders().getLocation().toString(),HttpMethod.GET, new HttpEntity<>(null,headers),
            String.class);


        if (response.getStatusCode() == HttpStatus.OK) {
            // The grant access page should be returned
            assertTrue(response.getBody().contains("<h1>Application Authorization</h1>"));

            formData.clear();
            formData.add(USER_OAUTH_APPROVAL, "true");
            formData.add(DEFAULT_CSRF_COOKIE_NAME, IntegrationTestUtils.extractCookieCsrf(response.getBody()));
            result = serverRunning.postForResponse("/oauth/authorize", headers, formData);
            assertEquals(HttpStatus.FOUND, result.getStatusCode());
            location = result.getHeaders().getLocation().toString();
        }
        else {
            // Token cached so no need for second approval
            assertEquals(HttpStatus.FOUND, response.getStatusCode());
            location = response.getHeaders().getLocation().toString();
        }
        if (StringUtils.hasText(redirectUri)) {
            assertTrue("Wrong location: " + location, location.matches(redirectUri + ".*code=.+"));
        }

        formData.clear();
        formData.add("client_id", clientId);
        formData.add("grant_type", "authorization_code");
        if (StringUtils.hasText(redirectUri)) {
            formData.add("redirect_uri", redirectUri);
        }
        if (StringUtils.hasText(tokenResponseType)) {
            formData.add("response_type", tokenResponseType);
        }
        formData.add("code", location.split("code=")[1].split("&")[0]);
        HttpHeaders tokenHeaders = new HttpHeaders();
        tokenHeaders.set("Authorization",testAccounts.getAuthorizationHeader(clientId, clientSecret));
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> tokenResponse = serverRunning.postForMap("/oauth/token", formData, tokenHeaders);
        assertEquals(HttpStatus.OK, tokenResponse.getStatusCode());

        @SuppressWarnings("unchecked")
        OAuth2AccessToken accessToken = DefaultOAuth2AccessToken.valueOf(tokenResponse.getBody());
        Map<String, String> body = tokenResponse.getBody();

        formData = new LinkedMultiValueMap<>();
        headers.set("Authorization", testAccounts.getAuthorizationHeader(clientId, clientSecret));
        formData.add("token", accessToken.getValue());

        if (callCheckToken) {
            tokenResponse = serverRunning.postForMap("/check_token", formData, headers);
            assertEquals(HttpStatus.OK, tokenResponse.getStatusCode());
            //System.err.println(tokenResponse.getBody());
            assertNotNull(tokenResponse.getBody().get("iss"));
        }
        return body;
    }

    public static boolean hasAuthority(String authority, Collection<GrantedAuthority> authorities) {
        for (GrantedAuthority a : authorities) {
            if (authority.equals(a.getAuthority())) {
                return true;
            }
        }
        return false;
    }

    public static String extractCookieCsrf(String body) {
        String pattern = "\\<input type=\\\"hidden\\\" name=\\\"X-Uaa-Csrf\\\" value=\\\"(.*?)\\\"";

        Pattern linkPattern = Pattern.compile(pattern);
        Matcher matcher = linkPattern.matcher(body);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    public static void takeScreenShot(WebDriver webDriver) {
        File scrFile = ((TakesScreenshot)webDriver).getScreenshotAs(OutputType.FILE);
        try {
            FileUtils.copyFile(scrFile, new File("testscreenshot-" + System.currentTimeMillis() + ".png"));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void clearAllButJsessionID(HttpHeaders headers) {
        String jsessionid = null;
        List<String> cookies = headers.get("Cookie");
        if (cookies!=null) {
            for (String cookie : cookies) {
                if (cookie.contains("JSESSIONID")) {
                    jsessionid = cookie;
                }
            }
        }
        if (jsessionid!=null) {
            headers.set("Cookie", jsessionid);
        } else {
            headers.remove("Cookie");
        }
    }

    public static class HttpRequestFactory extends HttpComponentsClientHttpRequestFactory {
        private final boolean disableRedirect;
        private final boolean disableCookieHandling;

        public HttpRequestFactory(boolean disableCookieHandling, boolean disableRedirect) {
            this.disableCookieHandling = disableCookieHandling;
            this.disableRedirect = disableRedirect;
        }

        @Override
        public HttpClient getHttpClient() {
            HttpClientBuilder builder = HttpClientBuilder.create()
                .useSystemProperties();
            if (disableRedirect) {
                builder = builder.disableRedirectHandling();
            }
            if (disableCookieHandling) {
                builder = builder.disableCookieManagement();
            }
            return  builder.build();
        }
    }


    public static class StatelessRequestFactory extends HttpRequestFactory {
        public StatelessRequestFactory() {
            super(true, true);
        }
    }

}
