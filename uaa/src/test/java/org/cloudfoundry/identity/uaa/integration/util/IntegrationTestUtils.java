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
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.junit.Assert;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.http.OAuth2ErrorHandler;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.URI;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class IntegrationTestUtils {

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
        resource.setAccessTokenUri(url+"/oauth/token");
        return resource;
    }

    public static RestTemplate getClientCredentialsTempate(ClientCredentialsResourceDetails details) {
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
        user.setPassword("secret");
        return client.postForEntity(url+"/Users", user, ScimUser.class).getBody();
    }

    @SuppressWarnings("rawtypes")
    public static Map findAllGroups(RestTemplate client,
                                    String url) {
        ResponseEntity<Map> response = client.getForEntity(url+"/Groups", Map.class);

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
            ResponseEntity<ScimGroup> group = client.getForEntity(url+"/Groups/{id}", ScimGroup.class, id);
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

    public static IdentityZone createZoneOrUpdateSubdomain(RestTemplate client,
                                                           String url,
                                                           String id,
                                                           String subdomain) {

        ResponseEntity<String> zoneGet = client.getForEntity(url + "/identity-zones/{id}", String.class, id);
        if (zoneGet.getStatusCode()==HttpStatus.OK) {
            IdentityZone existing = JsonUtils.readValue(zoneGet.getBody(), IdentityZone.class);
            existing.setSubdomain(subdomain);
            client.put(url + "/identity-zones/{id}", existing, id);
            return existing;
        }
        IdentityZone identityZone = fixtureIdentityZone(id, subdomain);

        ResponseEntity<IdentityZone> zone = client.postForEntity(url + "/identity-zones", identityZone, IdentityZone.class);
        return zone.getBody();
    }

    public static void makeZoneAdmin(RestTemplate client,
                                     String url,
                                     String userId,
                                     String zoneId) {
        ScimGroupMember member = new ScimGroupMember(userId);
        String groupName = "zones."+zoneId+".admin";
        ScimGroup group = new ScimGroup(groupName);
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

    public static IdentityProvider createOrUpdateProvider(String accessToken,
                                                          String url,
                                                          IdentityProvider provider) {
        RestTemplate client = new RestTemplate();
        MultiValueMap<String,String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer "+accessToken);
        headers.add("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        headers.add(IdentityZoneSwitchingFilter.HEADER, provider.getIdentityZoneId());
        HttpEntity getHeaders = new HttpEntity(headers);
        ResponseEntity<String> providerGet = client.exchange(
            url + "/identity-providers",
            HttpMethod.GET,
            getHeaders,
            String.class
        );
        if (providerGet!=null && providerGet.getStatusCode()==HttpStatus.OK) {
            List<IdentityProvider> existing = JsonUtils.readValue(providerGet.getBody(), new TypeReference<List<IdentityProvider>>() {});
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
        IdentityZone identityZone = new IdentityZone();
        identityZone.setId(id);
        identityZone.setSubdomain(subdomain);
        identityZone.setName("The Twiglet Zone["+id+"]");
        identityZone.setDescription("Like the Twilight Zone but tastier["+id+"].");
        return identityZone;
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
        HttpHeaders headers = new HttpHeaders();
        // TODO: should be able to handle just TEXT_HTML
        headers.setAccept(Arrays.asList(MediaType.TEXT_HTML, MediaType.ALL));

        AuthorizationCodeResourceDetails resource = testAccounts.getDefaultAuthorizationCodeResource();
        resource.setClientId(clientId);
        resource.setClientSecret(clientSecret);

        URI uri = serverRunning.buildUri("/oauth/authorize").queryParam("response_type", "code")
            .queryParam("state", "mystateid").queryParam("client_id", resource.getClientId())
            .queryParam("redirect_uri", resource.getPreEstablishedRedirectUri()).build();
        ResponseEntity<Void> result = serverRunning.getForResponse(uri.toString(), headers);
        assertEquals(HttpStatus.FOUND, result.getStatusCode());
        String location = result.getHeaders().getLocation().toString();

        if (result.getHeaders().containsKey("Set-Cookie")) {
            String cookie = result.getHeaders().getFirst("Set-Cookie");
            headers.set("Cookie", cookie);
        }

        ResponseEntity<String> response = serverRunning.getForString(location, headers);
        // should be directed to the login screen...
        assertTrue(response.getBody().contains("/login.do"));
        assertTrue(response.getBody().contains("username"));
        assertTrue(response.getBody().contains("password"));

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add("username", username);
        formData.add("password", password);

        // Should be redirected to the original URL, but now authenticated
        result = serverRunning.postForResponse("/login.do", headers, formData);
        assertEquals(HttpStatus.FOUND, result.getStatusCode());

        if (result.getHeaders().containsKey("Set-Cookie")) {
            String cookie = result.getHeaders().getFirst("Set-Cookie");
            headers.set("Cookie", cookie);
        }

        response = serverRunning.getForString(result.getHeaders().getLocation().toString(), headers);
        if (response.getStatusCode() == HttpStatus.OK) {
            // The grant access page should be returned
            assertTrue(response.getBody().contains("<h1>Application Authorization</h1>"));

            formData.clear();
            formData.add("user_oauth_approval", "true");
            result = serverRunning.postForResponse("/oauth/authorize", headers, formData);
            assertEquals(HttpStatus.FOUND, result.getStatusCode());
            location = result.getHeaders().getLocation().toString();
        }
        else {
            // Token cached so no need for second approval
            assertEquals(HttpStatus.FOUND, response.getStatusCode());
            location = response.getHeaders().getLocation().toString();
        }
        assertTrue("Wrong location: " + location,
            location.matches(resource.getPreEstablishedRedirectUri() + ".*code=.+"));

        formData.clear();
        formData.add("client_id", resource.getClientId());
        formData.add("redirect_uri", resource.getPreEstablishedRedirectUri());
        formData.add("grant_type", "authorization_code");
        formData.add("code", location.split("code=")[1].split("&")[0]);
        HttpHeaders tokenHeaders = new HttpHeaders();
        tokenHeaders.set("Authorization",
            testAccounts.getAuthorizationHeader(resource.getClientId(), resource.getClientSecret()));
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> tokenResponse = serverRunning.postForMap("/oauth/token", formData, tokenHeaders);
        assertEquals(HttpStatus.OK, tokenResponse.getStatusCode());
        @SuppressWarnings("unchecked")
        Map<String, String> body = tokenResponse.getBody();
        return body.get("access_token");
    }

    public static boolean hasAuthority(String authority, Collection<GrantedAuthority> authorities) {
        for (GrantedAuthority a : authorities) {
            if (authority.equals(a.getAuthority())) {
                return true;
            }
        }
        return false;
    }

    public static class StatelessRequestFactory extends HttpComponentsClientHttpRequestFactory {
        @Override
        public HttpClient getHttpClient() {
            return HttpClientBuilder.create()
                .useSystemProperties()
                .disableRedirectHandling()
                .disableCookieManagement()
                .build();
        }
    }

}
