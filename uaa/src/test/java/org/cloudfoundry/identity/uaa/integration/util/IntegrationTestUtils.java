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

import com.dumbster.smtp.SimpleSmtpServer;
import com.dumbster.smtp.SmtpMessage;
import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.io.FileUtils;
import org.apache.http.client.CookieStore;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.cookie.BasicClientCookie;
import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.account.UserInfoResponse;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.integration.feature.TestClient;
import org.cloudfoundry.identity.uaa.mfa_provider.GoogleMfaProviderConfig;
import org.cloudfoundry.identity.uaa.mfa_provider.MfaProvider;
import org.cloudfoundry.identity.uaa.provider.AbstractXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.resources.SearchResults;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUser.PhoneNumber;
import org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.hamcrest.Description;
import org.hamcrest.Matchers;
import org.hamcrest.TypeSafeMatcher;
import org.junit.Assert;
import org.openqa.selenium.By;
import org.openqa.selenium.Cookie;
import org.openqa.selenium.OutputType;
import org.openqa.selenium.TakesScreenshot;
import org.openqa.selenium.WebDriver;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
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
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.io.File;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME;
import static org.cloudfoundry.identity.uaa.util.UaaHttpRequestUtils.createRequestFactory;
import static org.hamcrest.core.StringStartsWith.startsWith;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.springframework.http.HttpHeaders.ACCEPT;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.USER_OAUTH_APPROVAL;
import static org.springframework.util.StringUtils.hasText;

public class IntegrationTestUtils {


    public static ScimUser createUnapprovedUser(ServerRunning serverRunning) throws Exception {
        String userName = "bob-" + new RandomValueStringGenerator().generate();
        String userEmail = userName + "@example.com";

        RestOperations restTemplate = serverRunning.getRestTemplate();

        ScimUser user = new ScimUser();
        user.setUserName(userName);
        user.setPassword("s3Cretsecret");
        user.addEmail(userEmail);
        user.setActive(true);
        user.setVerified(true);

        ResponseEntity<ScimUser> result = restTemplate.postForEntity(serverRunning.getUrl("/Users"), user, ScimUser.class);
        assertEquals(HttpStatus.CREATED, result.getStatusCode());

        return user;
    }

    public static boolean isMember(String userId, ScimGroup group) {
        for (ScimGroupMember member : group.getMembers()) {
            if(userId.equals(member.getMemberId())) {
                return true;
            }
        }
        return false;
    }


    public static UserInfoResponse getUserInfo(String url, String token) throws URISyntaxException {
        RestTemplate rest = new RestTemplate(createRequestFactory(true));
        MultiValueMap<String,String> headers = new LinkedMultiValueMap<>();
        headers.add(AUTHORIZATION, "Bearer "+token);
        headers.add(ACCEPT, APPLICATION_JSON_VALUE);
        RequestEntity<Void> request = new RequestEntity<>(headers, HttpMethod.GET, new URI(url+"/userinfo"));
        return rest.exchange(request, UserInfoResponse.class).getBody();
    }

    public static void deleteZone(String baseUrl, String id, String adminToken) throws URISyntaxException {
        RestTemplate rest = new RestTemplate(createRequestFactory(true));
        MultiValueMap<String,String> headers = new LinkedMultiValueMap<>();
        headers.add(AUTHORIZATION, "Bearer "+adminToken);
        headers.add(ACCEPT, APPLICATION_JSON_VALUE);
        RequestEntity<Void> request = new RequestEntity<>(headers, HttpMethod.DELETE, new URI(baseUrl+"/identity-zones/"+id));
        rest.exchange(request, Void.class);
    }

    public static MfaProvider createGoogleMfaProvider(String url, String token, MfaProvider<GoogleMfaProviderConfig> provider, String zoneSwitchId) {
        RestTemplate template = new RestTemplate();
        MultiValueMap<String,String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + token);
        headers.add("Content-Type", APPLICATION_JSON_VALUE);
        if (hasText(zoneSwitchId)) {
            headers.add(IdentityZoneSwitchingFilter.HEADER, zoneSwitchId);
        }
        HttpEntity getHeaders = new HttpEntity(provider,headers);
        ResponseEntity<MfaProvider> providerResponse = template.exchange(
                url+"/mfa-providers",
                HttpMethod.POST,
                getHeaders,
                MfaProvider.class
        );
        if (providerResponse.getStatusCode() == HttpStatus.CREATED) {
            return providerResponse.getBody();
        }
        throw new RuntimeException("Invalid return code:"+providerResponse.getStatusCode());

    }

    public static class RegexMatcher extends TypeSafeMatcher<String> {

        private final String regex;

        public RegexMatcher(final String regex) {
            this.regex = regex;
        }

        @Override
        public void describeTo(final Description description) {
            description.appendText("matches regex=`" + regex + "`");
        }

        @Override
        public boolean matchesSafely(final String string) {
            return string.matches(regex);
        }


        public static RegexMatcher matchesRegex(final String regex) {
            return new RegexMatcher(regex);
        }
    }

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
        return createUserWithPhone(client, url, username, firstName, lastName, email, verified, null);
    }
    public static ScimUser createUserWithPhone(RestTemplate client,
                                               String url,
                                               String username,
                                               String firstName,
                                               String lastName,
                                               String email,
                                               boolean verified,
                                               String phoneNumber) {
        ScimUser user = new ScimUser();
        user.setUserName(username);
        user.setName(new ScimUser.Name(firstName, lastName));
        user.addEmail(email);
        user.setVerified(verified);
        user.setActive(true);
        user.setPassword("secr3T");
        user.setPhoneNumbers(Collections.singletonList(new PhoneNumber(phoneNumber)));
        return client.postForEntity(url+"/Users", user, ScimUser.class).getBody();
    }

    public static ScimUser createUser(String token, String url, ScimUser user, String zoneSwitchId) {
        RestTemplate template = new RestTemplate();
        MultiValueMap<String,String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + token);
        headers.add("Content-Type", APPLICATION_JSON_VALUE);
        headers.add("If-Match", String.valueOf(user.getVersion()));
        if (hasText(zoneSwitchId)) {
            headers.add(IdentityZoneSwitchingFilter.HEADER, zoneSwitchId);
        }
        HttpEntity getHeaders = new HttpEntity(user,headers);
        ResponseEntity<ScimUser> userInfoGet = template.exchange(
            url+"/Users",
            HttpMethod.POST,
            getHeaders,
            ScimUser.class
        );
        if (userInfoGet.getStatusCode() == HttpStatus.CREATED) {
            return userInfoGet.getBody();
        }
        throw new RuntimeException("Invalid return code:"+userInfoGet.getStatusCode());
    }

    public static ScimUser updateUser(String token, String url, ScimUser user) {
        RestTemplate template = new RestTemplate();
        MultiValueMap<String,String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + token);
        headers.add("Content-Type", APPLICATION_JSON_VALUE);
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

    public static ScimUser getUserByZone(String token, String url, String subdomain, String username) {
        RestTemplate template = new RestTemplate();
        MultiValueMap<String,String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + token);
        headers.add("Content-Type", APPLICATION_JSON_VALUE);
        headers.add("X-Identity-Zone-Subdomain", subdomain);
        HttpEntity getHeaders = new HttpEntity(headers);
        ResponseEntity<String> userInfoGet = template.exchange(
            url+"/Users"
                + "?filter=userName eq \"" + username + "\"",
            HttpMethod.GET,
            getHeaders,
            String.class
        );
        ScimUser user = null;
        if (userInfoGet.getStatusCode() == HttpStatus.OK) {

            SearchResults<ScimUser> results = JsonUtils.readValue(userInfoGet.getBody(), SearchResults.class);
            List<ScimUser> resources = (List) results.getResources();
            if (resources.size() < 1) {
                return null;
            }
            user = JsonUtils.readValue(JsonUtils.writeValueAsString(resources.get(0)), ScimUser.class);
        }
        return user;
    }

    public static ScimUser getUser(String token, String url, String userId) {
        RestTemplate template = new RestTemplate();
        MultiValueMap<String,String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + token);
        headers.add("Content-Type", APPLICATION_JSON_VALUE);
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
        headers.add("Accept", APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + token);
        headers.add("Content-Type", APPLICATION_JSON_VALUE);
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
        headers.add("Accept", APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + zoneAdminToken);
        headers.add("Content-Type", APPLICATION_JSON_VALUE);
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
        headers.add("Accept", APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + token);
        headers.add("Content-Type", APPLICATION_JSON_VALUE);
        if (hasText(zoneId)) {
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
        headers.add("Accept", APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + token);
        headers.add("Content-Type", APPLICATION_JSON_VALUE);
        if (hasText(zoneId)) {
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
        headers.add("Accept", APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + token);
        headers.add("If-Match", "*");
        headers.add("Content-Type", APPLICATION_JSON_VALUE);
        if (hasText(zoneId)) {
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
        headers.add("Accept", APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + token);
        headers.add("Content-Type", APPLICATION_JSON_VALUE);
        if (hasText(zoneId)) {
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
            HttpEntity<IdentityZone> updateZoneRequest = new HttpEntity<>(existing);
            ResponseEntity<String> getUpdatedZone = client.exchange(url + "/identity-zones/{id}", HttpMethod.PUT, updateZoneRequest, String.class, id);
            IdentityZone updatedZone = JsonUtils.readValue(getUpdatedZone.getBody(), IdentityZone.class);
            return updatedZone;
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
        headers.add("Accept", APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer "+zoneAdminToken);
        headers.add("Content-Type", APPLICATION_JSON_VALUE);
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
        headers.add("Accept", APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer "+ adminToken);
        headers.add("Content-Type", APPLICATION_JSON_VALUE);
        if (hasText(switchToZoneId)) {
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
        throw new RuntimeException("Invalid create return code:"+clientCreate.getStatusCode());
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
        headers.add("Accept", APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + zoneAdminToken);
        headers.add("Content-Type", APPLICATION_JSON_VALUE);
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
        OIDCIdentityProviderDefinition config = new OIDCIdentityProviderDefinition();
        config.addAttributeMapping(USER_NAME_ATTRIBUTE_NAME, "user_name");
        config.setAuthUrl(new URL("https://oidc10.uaa-acceptance.cf-app.com/oauth/authorize"));
        config.setTokenUrl(new URL("https://oidc10.uaa-acceptance.cf-app.com/oauth/token"));
        config.setTokenKeyUrl(new URL("https://oidc10.uaa-acceptance.cf-app.com/token_key"));
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
        return getZoneAdminToken(baseUrl, serverRunning, OriginKeys.UAA);
    }

    public static String getZoneAdminToken(String baseUrl, ServerRunning serverRunning, String zoneId) throws Exception {
        RestTemplate identityClient = IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "identity", "identitysecret")
        );
        RestTemplate adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "admin", "adminsecret")
        );
        String email = new RandomValueStringGenerator().generate() +"@samltesting.org";
        ScimUser user = IntegrationTestUtils.createUser(adminClient, baseUrl, email, "firstname", "lastname", email, true);
        IntegrationTestUtils.makeZoneAdmin(identityClient, baseUrl, user.getId(), zoneId);

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
        String idpMetaData = "simplesamlphp".equals(alias) ?
            "http://simplesamlphp.cfapps.io/saml2/idp/metadata.php" :
            "http://simplesamlphp2.cfapps.io/saml2/idp/metadata.php";
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
        headers.add("Accept", APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer "+accessToken);
        headers.add("Content-Type", APPLICATION_JSON_VALUE);
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
        if (hasText(scopes)) {
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

    public static HttpHeaders getHeaders(CookieStore cookies) {
        HttpHeaders headers = new HttpHeaders();

        // TODO: should be able to handle just TEXT_HTML
        headers.setAccept(Arrays.asList(MediaType.TEXT_HTML, MediaType.ALL));

        for( org.apache.http.cookie.Cookie cookie : cookies.getCookies()) {
            headers.add("Cookie", cookie.getName() + "=" + cookie.getValue());
        }
        return headers;
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
        BasicCookieStore cookies = new BasicCookieStore();
        // TODO Fix to use json API rather than HTML
        if (hasText(jSessionId)) {
            cookies.addCookie(new BasicClientCookie("JSESSIONID", jSessionId));
        }

        String mystateid = "mystateid";
        ServerRunning.UriBuilder builder = serverRunning.buildUri("/oauth/authorize")
                .queryParam("response_type", "code")
                .queryParam("state", mystateid)
                .queryParam("client_id", clientId);
        if( hasText(redirectUri)) {
            builder = builder.queryParam("redirect_uri", redirectUri);
        }
        URI uri = builder.build();

        ResponseEntity<Void> result =
            serverRunning.createRestTemplate().exchange(
                uri.toString(),
                HttpMethod.GET,
                new HttpEntity<>(null, getHeaders(cookies)),
                Void.class
            );

        assertEquals(HttpStatus.FOUND, result.getStatusCode());
        String location = result.getHeaders().getLocation().toString();

        if (result.getHeaders().containsKey("Set-Cookie")) {
            for (String header : result.getHeaders().get("Set-Cookie")) {
                int nameLength = header.indexOf('=');
                cookies.addCookie(new BasicClientCookie(header.substring(0, nameLength), header.substring(nameLength+1)));
            }
        }

        ResponseEntity<String> response = serverRunning.getForString(location, getHeaders(cookies));

        if (response.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : response.getHeaders().get("Set-Cookie")) {
                int nameLength = cookie.indexOf('=');
                cookies.addCookie(new BasicClientCookie(cookie.substring(0, nameLength), cookie.substring(nameLength+1)));
            }
        }

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        if (!hasText(jSessionId)) {
            // should be directed to the login screen...
            assertTrue(response.getBody().contains("/login.do"));
            assertTrue(response.getBody().contains("username"));
            assertTrue(response.getBody().contains("password"));
            String csrf = IntegrationTestUtils.extractCookieCsrf(response.getBody());

            formData.add("username", username);
            formData.add("password", password);
            formData.add(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, csrf);

            // Should be redirected to the original URL, but now authenticated
            result = serverRunning.postForResponse("/login.do", getHeaders(cookies), formData);
            assertEquals(HttpStatus.FOUND, result.getStatusCode());

            cookies.clear();
            if (result.getHeaders().containsKey("Set-Cookie")) {
                for (String cookie : result.getHeaders().get("Set-Cookie")) {
                    int nameLength = cookie.indexOf('=');
                    cookies.addCookie(new BasicClientCookie(cookie.substring(0, nameLength), cookie.substring(nameLength+1)));
                }
            }
        }

        response = serverRunning.createRestTemplate().exchange(
            result.getHeaders().getLocation().toString(),HttpMethod.GET, new HttpEntity<>(null,getHeaders(cookies)),
            String.class);

        if (response.getHeaders().containsKey("Set-Cookie")) {
            for (String cookie : response.getHeaders().get("Set-Cookie")) {
                int nameLength = cookie.indexOf('=');
                cookies.addCookie(new BasicClientCookie(cookie.substring(0, nameLength), cookie.substring(nameLength+1)));
            }
        }
        if (response.getStatusCode() == HttpStatus.OK) {
            // The grant access page should be returned
            assertTrue(response.getBody().contains("<h1>Application Authorization</h1>"));

            formData.clear();
            formData.add(USER_OAUTH_APPROVAL, "true");
            formData.add(DEFAULT_CSRF_COOKIE_NAME, IntegrationTestUtils.extractCookieCsrf(response.getBody()));
            result = serverRunning.postForResponse("/oauth/authorize", getHeaders(cookies), formData);
            assertEquals(HttpStatus.FOUND, result.getStatusCode());
            location = result.getHeaders().getLocation().toString();
        }
        else {
            // Token cached so no need for second approval
            assertEquals(HttpStatus.FOUND, response.getStatusCode());
            location = response.getHeaders().getLocation().toString();
        }
        if (hasText(redirectUri)) {
            assertTrue("Wrong location: " + location, location.matches(redirectUri + ".*code=.+"));
        }

        formData.clear();
        formData.add("client_id", clientId);
        formData.add("grant_type", "authorization_code");
        if (hasText(redirectUri)) {
            formData.add("redirect_uri", redirectUri);
        }
        if (hasText(tokenResponseType)) {
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
        HttpHeaders headers = new HttpHeaders();
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
        takeScreenShot("testscreenshot-", webDriver);
    }
    public static void takeScreenShot(String prefix, WebDriver webDriver) {
        File scrFile = ((TakesScreenshot)webDriver).getScreenshotAs(OutputType.FILE);
        try {
            SimpleDateFormat format = new SimpleDateFormat("yyyyMMdd-HHmmss.SSS");
            String now = format.format(new Date(System.currentTimeMillis()));
            FileUtils.copyFile(scrFile, new File("build/reports/", prefix + now + ".png"));
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

    public static void validateAccountChooserCookie(String baseUrl, WebDriver webDriver) {
        List<String> cookies = getAccountChooserCookies(baseUrl, webDriver);
        assertThat(cookies, Matchers.hasItem(startsWith("Saved-Account-")));
    }

    public static void validateUserLastLogon(ScimUser user, Long beforeTestTime, Long afterTestTime) {
        Long userLastLogon = user.getLastLogonTime();
        assertNotNull(userLastLogon);
        assertTrue((userLastLogon > beforeTestTime) && (userLastLogon < afterTestTime));
    }

    public static List<String> getAccountChooserCookies(String baseUrl, WebDriver webDriver) {
        webDriver.get(baseUrl +"/logout.do");
        webDriver.get(baseUrl +"/login");
        return webDriver.manage().getCookies().stream().map(Cookie::getName).collect(Collectors.toList());
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

    public static String createAnotherUser(WebDriver webDriver, String password, SimpleSmtpServer simpleSmtpServer, String url, TestClient testClient) {
        String userEmail = "user" + new SecureRandom().nextInt() + "@example.com";

        webDriver.get(url + "/create_account");
        webDriver.findElement(By.name("email")).sendKeys(userEmail);
        webDriver.findElement(By.name("password")).sendKeys(password);
        webDriver.findElement(By.name("password_confirmation")).sendKeys(password);
        webDriver.findElement(By.xpath("//input[@value='Send activation link']")).click();

        Iterator receivedEmail = simpleSmtpServer.getReceivedEmail();
        SmtpMessage message = (SmtpMessage) receivedEmail.next();
        receivedEmail.remove();
        webDriver.get(testClient.extractLink(message.getBody()));

        return userEmail;
    }


    public static class StatelessRequestFactory extends HttpRequestFactory {
        public StatelessRequestFactory() {
            super(true, true);
        }
    }

}
