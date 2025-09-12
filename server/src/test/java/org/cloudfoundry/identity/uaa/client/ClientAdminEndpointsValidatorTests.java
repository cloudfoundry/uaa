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
import org.cloudfoundry.identity.uaa.security.beans.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.zone.ClientSecretPolicy;
import org.cloudfoundry.identity.uaa.zone.ClientSecretValidator;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.ZoneAwareClientSecretPolicyValidator;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_IMPLICIT;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_SAML2_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_USER_TOKEN;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ClientAdminEndpointsValidatorTests {

    BaseClientDetails client;
    BaseClientDetails caller;
    ClientAdminEndpointsValidator validator;
    ClientSecretValidator secretValidator;

    private List wildCardUrls = Arrays.asList("*", "**", "*/**", "**/*", "*/*", "**/**");
    private List httpWildCardUrls = Arrays.asList(
        "http://*",
        "http://**",
        "http://*/**",
        "http://*/*",
        "http://**/*",
        "http://a*",
        "http://*domain*",
        "http://*domain.com",
        "http://*domain/path",
        "http://**/path");

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Before
    public void createClient() {
        client = new BaseClientDetails("newclient","","","client_credentials","");
        client.setClientSecret("secret");
        caller = new BaseClientDetails("caller","","","client_credentials","clients.write");
        SecurityContextAccessor mockSecurityContextAccessor = mock(SecurityContextAccessor.class);
        validator = new ClientAdminEndpointsValidator(mockSecurityContextAccessor);
        secretValidator = new ZoneAwareClientSecretPolicyValidator(new ClientSecretPolicy(0,255,0,0,0,0,6));
        validator.setClientSecretValidator(secretValidator);

        QueryableResourceManager<ClientDetails> clientDetailsService = mock(QueryableResourceManager.class);
        when(mockSecurityContextAccessor.isAdmin()).thenReturn(false);
        when(mockSecurityContextAccessor.getScopes()).thenReturn(Collections.singletonList("clients.write"));
        String clientId = caller.getClientId();
        when(mockSecurityContextAccessor.getClientId()).thenReturn(clientId);
        String zoneId = IdentityZoneHolder.get().getId();
        when(clientDetailsService.retrieve(eq(clientId), eq(zoneId))).thenReturn(caller);
        validator.setClientDetailsService(clientDetailsService);
    }

    @Test
    public void test_validate_user_token_grant_type() {
        client.setAuthorizedGrantTypes(Collections.singletonList(GRANT_TYPE_USER_TOKEN));
        client.setRegisteredRedirectUri(Collections.singleton("http://anything.com"));
        validator.validate(client, true, true);
    }

    @Test
    public void test_validate_saml_bearer_grant_type() {
        client.setAuthorizedGrantTypes(Collections.singletonList(GRANT_TYPE_SAML2_BEARER));
        client.setRegisteredRedirectUri(Collections.singleton("http://anything.com"));
        validator.validate(client, true, true);
    }

    @Test
    public void test_validate_jwt_bearer_grant_type() {
        client.setAuthorizedGrantTypes(Collections.singletonList(GRANT_TYPE_JWT_BEARER));
        client.setScope(Collections.singletonList(caller.getClientId() + ".read"));
        client.setRegisteredRedirectUri(Collections.singleton("http://anything.com"));
        validator.validate(client, true, true);
    }

    public void validate_rejectsMalformedUrls() {
        client.setAuthorizedGrantTypes(Collections.singletonList(GRANT_TYPE_AUTHORIZATION_CODE));
        client.setRegisteredRedirectUri(Collections.singleton("httasdfasp://anything.comadfsfdasfdsa"));

        validator.validate(client, true, true);
    }

    @Test
    public void validate_allowsAUrlWithUnderscore() {
        client.setAuthorizedGrantTypes(Collections.singletonList(GRANT_TYPE_AUTHORIZATION_CODE));
        client.setRegisteredRedirectUri(Collections.singleton("http://foo_name.anything.com/"));

        validator.validate(client, true, true);
    }

    @Test
    public void test_validate_jwt_bearer_grant_type_without_secret_for_update() {
        client.setAuthorizedGrantTypes(Collections.singletonList(GRANT_TYPE_JWT_BEARER));
        client.setScope(Collections.singleton(caller.getClientId()+".write"));
        client.setClientSecret("");
        validator.validate(client, false, true);
    }

    @Ignore("GE Fork has its own JWT-bearer implementation")
    @Test
    public void test_validate_jwt_bearer_grant_type_without_secret() {
        client.setAuthorizedGrantTypes(Collections.singletonList(GRANT_TYPE_JWT_BEARER));
        client.setScope(Collections.singleton(caller.getClientId()+".write"));
        client.setClientSecret("");
        expectedException.expect(InvalidClientDetailsException.class);
        expectedException.expectMessage("Client secret is required for grant type "+GRANT_TYPE_JWT_BEARER);
        validator.validate(client, true, true);
    }

    @Ignore("GE Fork has its own JWT-bearer implementation")
    @Test
    public void test_validate_jwt_bearer_grant_type_without_scopes() {
        client.setAuthorizedGrantTypes(Collections.singletonList(GRANT_TYPE_JWT_BEARER));
        expectedException.expect(InvalidClientDetailsException.class);
        expectedException.expectMessage("Scope cannot be empty for grant_type "+GRANT_TYPE_JWT_BEARER);
        validator.validate(client, true, true);
    }

    @Test
    public void testValidate_Should_Allow_Prefix_Names() {

        client.setAuthorities(Collections.singletonList(new SimpleGrantedAuthority("uaa.resource")));
        client.setRegisteredRedirectUri(Collections.singleton("http://anything.com"));
        validator.validate(client, true, true);
        client.setAuthorities(Collections.singletonList(new SimpleGrantedAuthority(caller.getClientId() + ".some.other.authority")));

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

        for(String s : Arrays.asList(new String[] {GRANT_TYPE_AUTHORIZATION_CODE, GRANT_TYPE_IMPLICIT})) {
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
        client.setAuthorizedGrantTypes(Collections.singleton(GRANT_TYPE_AUTHORIZATION_CODE));
        client.setRegisteredRedirectUri(urls);
        validator.validateClientRedirectUri(client);
    }

    @Test(expected = InvalidClientDetailsException.class)
    public void testAnotherOptionOneInvalidURL() {
        Set<String> urls = new HashSet<>();
        urls.add("http://valid.com");
        urls.add("http://invalid.com/with/path,subpath");
        client.setAuthorizedGrantTypes(Collections.singleton(GRANT_TYPE_AUTHORIZATION_CODE));
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
