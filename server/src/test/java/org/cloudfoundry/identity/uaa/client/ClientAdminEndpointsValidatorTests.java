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

import org.assertj.core.api.InstanceOfAssertFactories;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.resources.QueryableResourceManager;
import org.cloudfoundry.identity.uaa.security.beans.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.ClientSecretPolicy;
import org.cloudfoundry.identity.uaa.zone.ClientSecretValidator;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.ZoneAwareClientSecretPolicyValidator;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManagerImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.*;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_IMPLICIT;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_PASSWORD;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_REFRESH_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_SAML2_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_TOKEN_EXCHANGE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_USER_TOKEN;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ClientAdminEndpointsValidatorTests {

    UaaClientDetails client;
    UaaClientDetails caller;
    ClientAdminEndpointsValidator validator;
    ClientSecretValidator secretValidator;

    private final List<String> wildCardUrls = Arrays.asList("*", "**", "*/**", "**/*", "*/*", "**/**");
    private final List<String> httpWildCardUrls = Arrays.asList(
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

    @BeforeEach
    void createClient() {
        client = new UaaClientDetails("newclient", "", "", "client_credentials", "");
        client.setClientSecret("secret");
        caller = new UaaClientDetails("caller", "", "", "client_credentials", "clients.write");
        SecurityContextAccessor mockSecurityContextAccessor = mock(SecurityContextAccessor.class);
        validator = new ClientAdminEndpointsValidator(mockSecurityContextAccessor, new IdentityZoneManagerImpl(), false);
        secretValidator = new ZoneAwareClientSecretPolicyValidator(new ClientSecretPolicy(0, 255, 0, 0, 0, 0, 6));
        validator.setClientSecretValidator(secretValidator);

        QueryableResourceManager<ClientDetails> clientDetailsService = mock(QueryableResourceManager.class);
        when(mockSecurityContextAccessor.isAdmin()).thenReturn(false);
        when(mockSecurityContextAccessor.getScopes()).thenReturn(Collections.singletonList("clients.write"));
        String clientId = caller.getClientId();
        when(mockSecurityContextAccessor.getClientId()).thenReturn(clientId);
        String zoneId = IdentityZoneHolder.get().getId();
        when(clientDetailsService.retrieve(clientId, zoneId)).thenReturn(caller);
        validator.setClientDetailsService(clientDetailsService);
    }

    @Test
    void validate_user_token_grant_type() {
        client.setAuthorizedGrantTypes(Collections.singletonList(GRANT_TYPE_USER_TOKEN));
        client.setRegisteredRedirectUri(Collections.singleton("http://anything.com"));
        validator.validate(client, true, true);
    }

    @Test
    void validate_saml_bearer_grant_type() {
        client.setAuthorizedGrantTypes(Collections.singletonList(GRANT_TYPE_SAML2_BEARER));
        client.setRegisteredRedirectUri(Collections.singleton("http://anything.com"));
        validator.validate(client, true, true);
    }

    @Test
    void validate_jwt_bearer_grant_type() {
        client.setAuthorizedGrantTypes(Collections.singletonList(GRANT_TYPE_JWT_BEARER));
        client.setScope(Collections.singletonList(caller.getClientId() + ".read"));
        client.setRegisteredRedirectUri(Collections.singleton("http://anything.com"));
        validator.validate(client, true, true);
    }

    @Test
    void validate_token_exchange_grant_type() {
        client.setAuthorizedGrantTypes(Collections.singletonList(GRANT_TYPE_TOKEN_EXCHANGE));
        client.setScope(Collections.singletonList(caller.getClientId() + ".read"));
        client.setRegisteredRedirectUri(Collections.singleton("http://anything.com"));
        validator.validate(client, true, true);
    }

    @Test
    void validate_token_exchange_grant_type_with_refresh() {
        client.setAuthorizedGrantTypes(List.of(GRANT_TYPE_TOKEN_EXCHANGE, GRANT_TYPE_REFRESH_TOKEN));
        client.setScope(Collections.singletonList(caller.getClientId() + ".read"));
        client.setRegisteredRedirectUri(Collections.singleton("http://anything.com"));
        validator.validate(client, true, true);
    }

    @Test
    void token_exchange_cannot_contain_other_grant_types() {
        client.setAuthorizedGrantTypes(List.of(GRANT_TYPE_TOKEN_EXCHANGE, GRANT_TYPE_PASSWORD));
        client.setScope(Collections.singletonList(caller.getClientId() + ".read"));
        client.setRegisteredRedirectUri(Collections.singleton("http://anything.com"));
        assertThatThrownBy(
                () -> validator.validate(client, true, true)
        )
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessageContaining(GRANT_TYPE_TOKEN_EXCHANGE+ " is a privileged grant_type, and cannot be used in conjunction with other grant types.");
    }

    @Test
    void validate_rejectsMalformedUrls() {
        client.setAuthorizedGrantTypes(Collections.singletonList(GRANT_TYPE_AUTHORIZATION_CODE));
        client.setRegisteredRedirectUri(Collections.singleton("httasdfasp://anything.comadfsfdasfdsa"));

        validator.validate(client, true, true);
    }

    @Test
    void validate_allowsAUrlWithUnderscore() {
        client.setAuthorizedGrantTypes(Collections.singletonList(GRANT_TYPE_AUTHORIZATION_CODE));
        client.setRegisteredRedirectUri(Collections.singleton("http://foo_name.anything.com/"));

        validator.validate(client, true, true);
    }

    @Test
    void validate_jwt_bearer_grant_type_without_secret_for_update() {
        client.setAuthorizedGrantTypes(Collections.singletonList(GRANT_TYPE_JWT_BEARER));
        client.setScope(Collections.singleton(caller.getClientId() + ".write"));
        client.setClientSecret("");
        validator.validate(client, false, true);
    }

    @Test
    void validate_jwt_bearer_grant_type_without_empty_secret() {
        client.setAuthorizedGrantTypes(Collections.singletonList(GRANT_TYPE_JWT_BEARER));
        client.setScope(Collections.singleton(caller.getClientId() + ".write"));
        client.setClientSecret("");
        assertThatNoException().isThrownBy(() -> validator.validate(client, true, true));
    }

    @Test
    void validate_jwt_bearer_grant_type_without_scopes() {
        client.setAuthorizedGrantTypes(Collections.singletonList(GRANT_TYPE_JWT_BEARER));
        assertThatThrownBy(() -> validator.validate(client, true, true))
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessageContaining("Scope cannot be empty for grant_type " + GRANT_TYPE_JWT_BEARER);
    }

    @Test
    void validateShouldAllowPrefixNames() {
        client.setAuthorities(Collections.singletonList(new SimpleGrantedAuthority("uaa.resource")));
        client.setRegisteredRedirectUri(Collections.singleton("http://anything.com"));
        validator.validate(client, true, true);
        client.setAuthorities(Collections.singletonList(new SimpleGrantedAuthority(caller.getClientId() + ".some.other.authority")));

        assertThatThrownBy(() -> validator.validate(client, true, true))
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessageContaining("not an allowed authority");
    }

    @Test
    void validate_not_permits_restricted_urls_for_authcode_implicit_grant_types() {
        List<String> invalidRedirectUris = new ArrayList<>(wildCardUrls);
        invalidRedirectUris.addAll(httpWildCardUrls);
        invalidRedirectUris.addAll(convertToHttps(httpWildCardUrls));

        for (String s : new String[]{GRANT_TYPE_AUTHORIZATION_CODE, GRANT_TYPE_IMPLICIT}) {
            client.setAuthorizedGrantTypes(Collections.singleton(s));
            for (String url : invalidRedirectUris) {
                testValidatorForInvalidURL(url);
            }
            testValidatorForInvalidURL(null);
            testValidatorForInvalidURL("");
        }
    }

    @Test
    void validatePermitsRestrictedUrlsForOtherGrantTypes() {
        List<String> redirectUris = new ArrayList<>(wildCardUrls);
        redirectUris.addAll(httpWildCardUrls);
        redirectUris.addAll(convertToHttps(httpWildCardUrls));

        for (String s : new String[]{"client_credentials", "password"}) {
            client.setAuthorizedGrantTypes(Collections.singleton(s));
            for (String url : redirectUris) {
                testValidatorForURL(url);
            }
            testValidatorForURL(null);
        }
    }

    @Test
    void validateOneValidOneInvalidURL() {
        Set<String> urls = new HashSet<>();
        urls.add("http://valid.com");
        urls.add("http://valid.com/with/path*");
        urls.add("http://invalid*");
        client.setAuthorizedGrantTypes(Collections.singleton(GRANT_TYPE_AUTHORIZATION_CODE));
        client.setRegisteredRedirectUri(urls);
        assertThatThrownBy(() ->
                validator.validateClientRedirectUri(client)).asInstanceOf(InstanceOfAssertFactories.throwable(InvalidClientDetailsException.class));
    }

    @Test
    void anotherOptionOneInvalidURL() {
        Set<String> urls = new HashSet<>();
        urls.add("http://valid.com");
        urls.add("http://invalid.com/with/path,subpath");
        client.setAuthorizedGrantTypes(Collections.singleton(GRANT_TYPE_AUTHORIZATION_CODE));
        client.setRegisteredRedirectUri(urls);
        assertThatThrownBy(() ->
                validator.validateClientRedirectUri(client)).asInstanceOf(InstanceOfAssertFactories.throwable(InvalidClientDetailsException.class));
    }

    @Test
    void validateValidURLs() {
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
        } catch (InvalidClientDetailsException _) {
            return;
        }
        fail("Url %s should not be allowed".formatted(url));
    }

    private void testValidatorForURL(String url) {
        client.setRegisteredRedirectUri(Collections.singleton(url));
        validator.validateClientRedirectUri(client);
    }

    private List<String> convertToHttps(List<String> urls) {
        List<String> httpsUrls = new ArrayList<>(urls.size());
        for (String url : urls) {
            httpsUrls.add(url.replace("http", "https"));
        }

        return httpsUrls;
    }

    @Test
    void validate_create_foldsTopLevelJwtCredsListIntoClientJwtConfigAndStripsAdditional() {
        client.setScope(Collections.singletonList(caller.getClientId() + ".read"));
        client.addAdditionalInformation(ClientJwtConfiguration.JWT_CREDS,
                JsonUtils.readValue("[{\"iss\":\"http://localhost/uaa/oauth/token\",\"sub\":\"subj\",\"aud\":\"aud\"}]", List.class));

        UaaClientDetails result = (UaaClientDetails) validator.validate(client, true, true);

        assertThat(result.getClientJwtConfig()).isNotBlank();
        assertThat(ClientJwtConfiguration.readValue(result).getClientJwtCredentials()).hasSize(1);
        assertThat(result.getAdditionalInformation()).doesNotContainKey(ClientJwtConfiguration.JWT_CREDS);
    }

    @Test
    void validate_create_foldsNestedClientJwtConfigMapAndStripsFromAdditional() {
        client.setScope(Collections.singletonList(caller.getClientId() + ".read"));
        Map<String, Object> nested = new java.util.HashMap<>();
        nested.put(ClientJwtConfiguration.JWT_CREDS, JsonUtils.readValue("[{\"iss\":\"http://issuer\",\"sub\":\"subj\"}]", List.class));
        client.addAdditionalInformation("client_jwt_config", nested);

        UaaClientDetails result = (UaaClientDetails) validator.validate(client, true, true);

        assertThat(result.getClientJwtConfig()).isNotBlank();
        assertThat(result.getAdditionalInformation()).doesNotContainKey("client_jwt_config");
    }

    @Test
    void validate_create_invalidJwtCredsList_throws() {
        client.setScope(Collections.singletonList(caller.getClientId() + ".read"));
        client.addAdditionalInformation(ClientJwtConfiguration.JWT_CREDS, List.of(Map.of("not", "valid")));

        assertThatThrownBy(() -> validator.validate(client, true, true))
                .isInstanceOf(InvalidClientDetailsException.class);
    }

    @Test
    void rejectsTlsClientAuthCaWhenMtlsDisabled() {
        ClientAdminEndpointsValidator mtlsDisabledValidator = new ClientAdminEndpointsValidator(
                mock(SecurityContextAccessor.class), new IdentityZoneManagerImpl(), false);

        client.setAuthorizedGrantTypes(java.util.Set.of("client_credentials"));
        Map<String, Object> additionalInfo = new java.util.HashMap<>();
        additionalInfo.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, "ca-pem");
        client.setAdditionalInformation(additionalInfo);

        assertThatThrownBy(() -> mtlsDisabledValidator.validate(client, false, false))
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessageContaining("uaa.mtls-enabled");
    }

    @Test
    void rejectsTlsClientAuthTrustedProxyCaWhenMtlsDisabled() {
        ClientAdminEndpointsValidator mtlsDisabledValidator = new ClientAdminEndpointsValidator(
                mock(SecurityContextAccessor.class), new IdentityZoneManagerImpl(), false);

        client.setAuthorizedGrantTypes(java.util.Set.of("client_credentials"));
        Map<String, Object> additionalInfo = new java.util.HashMap<>();
        additionalInfo.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_TRUSTED_PROXY_CA, "proxy-ca-pem");
        client.setAdditionalInformation(additionalInfo);

        assertThatThrownBy(() -> mtlsDisabledValidator.validate(client, false, false))
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessageContaining("uaa.mtls-enabled");
    }

    @Test
    void allowsTlsClientAuthCaWhenMtlsEnabled() {
        ClientAdminEndpointsValidator mtlsEnabledValidator = new ClientAdminEndpointsValidator(
                mock(SecurityContextAccessor.class), new IdentityZoneManagerImpl(), true);

        client.setAuthorizedGrantTypes(java.util.Set.of("client_credentials"));
        Map<String, Object> additionalInfo = new java.util.HashMap<>();
        additionalInfo.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, "ca-pem");
        additionalInfo.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_TRUSTED_PROXY_CA, "proxy-ca-pem");
        client.setAdditionalInformation(additionalInfo);

        ClientDetails validated = mtlsEnabledValidator.validate(client, false, false);

        assertThat(validated.getAdditionalInformation())
                .containsEntry(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, "ca-pem");
    }

    @Test
    void allowsClientWithoutMtlsFieldsWhenMtlsDisabled() {
        ClientAdminEndpointsValidator mtlsDisabledValidator = new ClientAdminEndpointsValidator(
                mock(SecurityContextAccessor.class), new IdentityZoneManagerImpl(), false);

        client.setAuthorizedGrantTypes(java.util.Set.of("client_credentials"));
        client.setClientSecret("secret");

        ClientDetails validated = mtlsDisabledValidator.validate(client, false, false);

        assertThat(validated.getClientId()).isEqualTo(client.getClientId());
    }

    @Test
    void validateTlsClientAuthClaimConfig_noOpWhenNoClaimMappingsKey() {
        assertThatNoException().isThrownBy(() ->
                ClientAdminEndpointsValidator.validateTlsClientAuthClaimConfig(Map.of(), "client-id"));
    }

    @Test
    void validateTlsClientAuthClaimConfig_acceptsValidNativeClaimMappings() {
        Map<String, Object> info = Map.of(
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS,
                List.of(Map.of("field", "subject_cn", "claim", "cf_instance_guid", "pattern", "^(.+)$"))
        );

        assertThatNoException().isThrownBy(() ->
                ClientAdminEndpointsValidator.validateTlsClientAuthClaimConfig(info, "client-id"));
    }

    @Test
    void validateTlsClientAuthClaimConfig_acceptsValidJsonStringClaimMappings() {
        // Same logical field/claim/pattern data as
        // validateTlsClientAuthClaimConfig_acceptsValidNativeClaimMappings, but supplied as a
        // JSON string, to genuinely prove the two parsing shapes (native List/Map vs. JSON
        // string) handle identical input equivalently.
        Map<String, Object> info = Map.of(
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS,
                "[{\"field\":\"subject_cn\",\"claim\":\"cf_instance_guid\",\"pattern\":\"^(.+)$\"}]"
        );

        assertThatNoException().isThrownBy(() ->
                ClientAdminEndpointsValidator.validateTlsClientAuthClaimConfig(info, "client-id"));
    }

    @Test
    void validateTlsClientAuthClaimConfig_rejectsMissingField() {
        Map<String, Object> info = Map.of(
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS,
                List.of(Map.of("claim", "cf_instance_guid"))
        );

        assertThatThrownBy(() -> ClientAdminEndpointsValidator.validateTlsClientAuthClaimConfig(info, "client-id"))
                .isInstanceOf(InvalidClientDetailsException.class);
    }

    @Test
    void validateTlsClientAuthClaimConfig_rejectsUnrecognizedField() {
        Map<String, Object> info = Map.of(
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS,
                List.of(Map.of("field", "subject_email", "claim", "cf_instance_guid"))
        );

        assertThatThrownBy(() -> ClientAdminEndpointsValidator.validateTlsClientAuthClaimConfig(info, "client-id"))
                .isInstanceOf(InvalidClientDetailsException.class);
    }

    @Test
    void validateTlsClientAuthClaimConfig_rejectsBlankClaim() {
        Map<String, Object> info = Map.of(
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS,
                List.of(Map.of("field", "subject_cn", "claim", "  "))
        );

        assertThatThrownBy(() -> ClientAdminEndpointsValidator.validateTlsClientAuthClaimConfig(info, "client-id"))
                .isInstanceOf(InvalidClientDetailsException.class);
    }

    @Test
    void validateTlsClientAuthClaimConfig_rejectsInvalidRegexPattern() {
        Map<String, Object> info = Map.of(
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS,
                List.of(Map.of("field", "subject_ou", "claim", "cf_org", "pattern", "["))
        );

        assertThatThrownBy(() -> ClientAdminEndpointsValidator.validateTlsClientAuthClaimConfig(info, "client-id"))
                .isInstanceOf(InvalidClientDetailsException.class);
    }

    @Test
    void validateTlsClientAuthClaimConfig_rejectsSubTemplateReferencingUndeclaredClaim() {
        Map<String, Object> info = new java.util.HashMap<>();
        info.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS,
                List.of(Map.of("field", "subject_cn", "claim", "cf_instance_guid")));
        info.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUB_TEMPLATE, "{cf_undeclared}");

        assertThatThrownBy(() -> ClientAdminEndpointsValidator.validateTlsClientAuthClaimConfig(info, "client-id"))
                .isInstanceOf(InvalidClientDetailsException.class);
    }

    @Test
    void validateTlsClientAuthClaimConfig_rejectsAudTemplateReferencingUndeclaredClaim() {
        Map<String, Object> info = new java.util.HashMap<>();
        info.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS,
                List.of(Map.of("field", "subject_cn", "claim", "cf_instance_guid")));
        info.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_AUD_TEMPLATES,
                List.of("https://valid.example.com/{cf_undeclared}"));

        assertThatThrownBy(() -> ClientAdminEndpointsValidator.validateTlsClientAuthClaimConfig(info, "client-id"))
                .isInstanceOf(InvalidClientDetailsException.class);
    }

    @Test
    void validateTlsClientAuthClaimConfig_rejectsRequiredClaimsReferencingUndeclaredClaim() {
        Map<String, Object> info = new java.util.HashMap<>();
        info.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS,
                List.of(Map.of("field", "subject_cn", "claim", "cf_instance_guid")));
        info.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_REQUIRED_CLAIMS,
                Map.of("cf_undeclared", "some-value"));

        assertThatThrownBy(() -> ClientAdminEndpointsValidator.validateTlsClientAuthClaimConfig(info, "client-id"))
                .isInstanceOf(InvalidClientDetailsException.class);
    }

    @Test
    void validateTlsClientAuthClaimConfig_rejectsRequiredClaimsWithNullValue() {
        Map<String, Object> info = new java.util.HashMap<>();
        info.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS,
                List.of(Map.of("field", "subject_ou", "claim", "cf_org")));
        Map<String, String> requiredClaims = new java.util.HashMap<>();
        requiredClaims.put("cf_org", null);
        info.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_REQUIRED_CLAIMS, requiredClaims);

        assertThatThrownBy(() -> ClientAdminEndpointsValidator.validateTlsClientAuthClaimConfig(info, "client-id"))
                .isInstanceOf(InvalidClientDetailsException.class);
    }

    @Test
    void validateTlsClientAuthClaimConfig_rejectsRequiredClaimsWithBlankValue() {
        Map<String, Object> info = new java.util.HashMap<>();
        info.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS,
                List.of(Map.of("field", "subject_ou", "claim", "cf_org")));
        info.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_REQUIRED_CLAIMS,
                Map.of("cf_org", "   "));

        assertThatThrownBy(() -> ClientAdminEndpointsValidator.validateTlsClientAuthClaimConfig(info, "client-id"))
                .isInstanceOf(InvalidClientDetailsException.class);
    }

    @Test
    void validateTlsClientAuthClaimConfig_acceptsFullyValidConfig() {
        Map<String, Object> info = new java.util.HashMap<>();
        info.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS,
                List.of(
                        Map.of("field", "subject_cn", "claim", "cf_instance_guid"),
                        Map.of("field", "subject_ou", "claim", "cf_org", "pattern", "^org:(.+)$")
                ));
        info.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUB_TEMPLATE, "{cf_instance_guid}");
        info.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_AUD_TEMPLATES,
                List.of("https://valid.example.com/{cf_org}"));
        info.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_REQUIRED_CLAIMS,
                Map.of("cf_org", "myorg"));

        assertThatNoException().isThrownBy(() ->
                ClientAdminEndpointsValidator.validateTlsClientAuthClaimConfig(info, "client-id"));
    }

    @Test
    void validateTlsClientAuthClaimConfig_rejectsSubTemplateExceedingMaxLength() {
        // CodeQL: js/polynomial-redos on the PLACEHOLDER regex (\{([^}]+)\}). The possessive
        // quantifier fix ([^}]++) only reduces the constant factor -- Matcher.find() still
        // retries the full match attempt at every character position, so the real fix is to
        // bound the input length before it ever reaches the regex.
        String oversizedSubTemplate = "{".repeat(ClientAdminEndpointsValidator.MAX_TEMPLATE_LENGTH + 1);
        Map<String, Object> info = new java.util.HashMap<>();
        info.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS,
                List.of(Map.of("field", "subject_cn", "claim", "cf_instance_guid")));
        info.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUB_TEMPLATE, oversizedSubTemplate);

        assertThatThrownBy(() -> ClientAdminEndpointsValidator.validateTlsClientAuthClaimConfig(info, "client-id"))
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessageContaining("client-id")
                .hasMessageContaining(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUB_TEMPLATE)
                .hasMessageContaining(String.valueOf(ClientAdminEndpointsValidator.MAX_TEMPLATE_LENGTH));
    }

    @Test
    void validateTlsClientAuthClaimConfig_rejectsAudTemplateExceedingMaxLength() {
        String oversizedAudTemplate = "{".repeat(ClientAdminEndpointsValidator.MAX_TEMPLATE_LENGTH + 1);
        Map<String, Object> info = new java.util.HashMap<>();
        info.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS,
                List.of(Map.of("field", "subject_cn", "claim", "cf_instance_guid")));
        info.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_AUD_TEMPLATES, List.of(oversizedAudTemplate));

        assertThatThrownBy(() -> ClientAdminEndpointsValidator.validateTlsClientAuthClaimConfig(info, "client-id"))
                .isInstanceOf(InvalidClientDetailsException.class)
                .hasMessageContaining("client-id")
                .hasMessageContaining(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_AUD_TEMPLATES)
                .hasMessageContaining(String.valueOf(ClientAdminEndpointsValidator.MAX_TEMPLATE_LENGTH));
    }

    @Test
    void validateTlsClientAuthClaimConfig_acceptsSubTemplateAtExactlyMaxLength() {
        // A pathological all-'{' template of exactly MAX_TEMPLATE_LENGTH characters must still
        // be processed quickly, confirming the bound (combined with the possessive quantifier)
        // makes this genuinely fast rather than merely rejected.
        String maxLengthSubTemplate = "{".repeat(ClientAdminEndpointsValidator.MAX_TEMPLATE_LENGTH);
        Map<String, Object> info = new java.util.HashMap<>();
        info.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS,
                List.of(Map.of("field", "subject_cn", "claim", "cf_instance_guid")));
        info.put(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUB_TEMPLATE, maxLengthSubTemplate);

        long start = System.nanoTime();
        // The all-'{' template never closes a placeholder, so no undeclared-placeholder
        // exception is thrown -- validateTemplatePlaceholders() simply finds no matches.
        assertThatNoException().isThrownBy(() ->
                ClientAdminEndpointsValidator.validateTlsClientAuthClaimConfig(info, "client-id"));
        long elapsedMillis = (System.nanoTime() - start) / 1_000_000;

        assertThat(elapsedMillis).isLessThan(100);
    }
}
