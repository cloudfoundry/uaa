/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.resources.QueryableResourceManager;
import org.cloudfoundry.identity.uaa.security.SecurityContextAccessor;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_SAML2_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_USER_TOKEN;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ClientAdminEndpointsValidatorTests {

    BaseClientDetails client;
    BaseClientDetails caller;
    ClientAdminEndpointsValidator validator;
    private List wildCardUrls = Arrays.asList("*", "**", "*/**", "**/*", "*/*", "**/**");
    private List httpWildCardUrls = Arrays.asList("http://*", "http://**", "http://*/**", "http://*/*", "http://**/*", "http://a*", "http://abc*.domain.com",
        "http://*domain*", "http://*domain.com", "http://*domain/path", "http://**/path");

    @Before
    public void createClient() throws Exception {
        client = new BaseClientDetails("newclient","","","client_credentials","");
        client.setClientSecret("secret");
        caller = new BaseClientDetails("caller","","","client_credentials","clients.write");
        validator = new ClientAdminEndpointsValidator();

        QueryableResourceManager<ClientDetails> clientDetailsService = mock(QueryableResourceManager.class);
        SecurityContextAccessor accessor = mock(SecurityContextAccessor.class);
        when(accessor.isAdmin()).thenReturn(false);
        when(accessor.getScopes()).thenReturn(Arrays.asList("clients.write"));
        when(accessor.getClientId()).thenReturn(caller.getClientId());
        when(clientDetailsService.retrieve(eq(caller.getClientId()))).thenReturn(caller);
        validator.setClientDetailsService(clientDetailsService);
        validator.setSecurityContextAccessor(accessor);

    }

    @Test
    public void test_validate_user_token_grant_type() throws Exception {
        client.setAuthorizedGrantTypes(Arrays.asList(GRANT_TYPE_USER_TOKEN));
        client.setRegisteredRedirectUri(Collections.singleton("http://anything.com"));
        validator.validate(client, true, true);
    }

    @Test
    public void test_validate_saml_bearer_grant_type() throws Exception {
        client.setAuthorizedGrantTypes(Arrays.asList(GRANT_TYPE_SAML2_BEARER));
        client.setRegisteredRedirectUri(Collections.singleton("http://anything.com"));
        validator.validate(client, true, true);
    }

    @Test
    public void testValidate_Should_Allow_Prefix_Names() throws Exception {

        client.setAuthorities(Arrays.asList(new SimpleGrantedAuthority("uaa.resource")));
        client.setRegisteredRedirectUri(Collections.singleton("http://anything.com"));
        validator.validate(client, true, true);
        client.setAuthorities(Arrays.asList(new SimpleGrantedAuthority(caller.getClientId()+".some.other.authority")));

        try {
            validator.validate(client, true, true);
            fail();
        } catch (InvalidClientDetailsException x) {
            assertThat(x.getMessage(), containsString("not an allowed authority"));
        }
    }

    @Test
    public void test_validate_not_permits_restricted_urls_for_authcode_implicit_grant_types() {
        List<String> invalidRedirectUris = new ArrayList<>(wildCardUrls);
        invalidRedirectUris.addAll(httpWildCardUrls);
        invalidRedirectUris.addAll(convertToHttps(httpWildCardUrls));

        for(String s : Arrays.asList(new String[] {"authorization_code", "implicit"})) {
            client.setAuthorizedGrantTypes(Collections.singleton(s));
            for(String url : invalidRedirectUris) {
                testValidatorForInvalidURL(url);
            }
            testValidatorForInvalidURL(null);
            testValidatorForInvalidURL("");
        }
    }

    @Test
    public void testValidate_permits_restricted_urls_for_other_grant_types() {
        List<String> redirectUris = new ArrayList<>(wildCardUrls);
        redirectUris.addAll(httpWildCardUrls);
        redirectUris.addAll(convertToHttps(httpWildCardUrls));

        for(String s : Arrays.asList(new String[] {"client_credentials", "password"})) {
            client.setAuthorizedGrantTypes(Collections.singleton(s));
            for(String url : redirectUris) {
                testValidatorForURL(url);
            }
            testValidatorForURL(null);
        }
    }

    @Test(expected = InvalidClientDetailsException.class)
    public void testValidateOneValidOneInvalidURL() {
        Set<String> urls = new HashSet<>();
        urls.add("http://valid.com");
        urls.add("http://valid.com/with/path*");
        urls.add("http://invalid*");
        client.setAuthorizedGrantTypes(Collections.singleton("authorization_code"));
        client.setRegisteredRedirectUri(urls);
        validator.validateClientRedirectUri(client);
    }

    @Test
    public void testValidateValidURLs() {
        Set<String> urls = new HashSet<>();
        urls.add("http://valid.com");
        urls.add("http://sub.valid.com");
        urls.add("http://valid.com/with/path");
        urls.add("https://subsub.sub.valid.com/**");
        urls.add("https://valid.com/path/*/path");
        urls.add("http://sub.valid.com/*/with/path**");
        client.setRegisteredRedirectUri(urls);
        validator.validateClientRedirectUri(client);
    }

    private void testValidatorForInvalidURL(String url) {
        try {
            testValidatorForURL(url);
        } catch (InvalidClientDetailsException e) {
            return;
        }
        Assert.fail(String.format("Url %s should not be allowed", url));
    }

    private void testValidatorForURL(String url) {
        client.setRegisteredRedirectUri(Collections.singleton(url));
        validator.validateClientRedirectUri(client);
    }

    private List<String> convertToHttps(List<String> urls) {
        List<String> httpsUrls = new ArrayList<>(urls.size());
        for(String url : urls) {
            httpsUrls.add(url.replace("http", "https"));
        }

        return httpsUrls;
    }
}
