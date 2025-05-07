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
import org.cloudfoundry.identity.uaa.oauth.client.resource.AuthorizationCodeResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.ClientCredentialsResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.ImplicitResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2ProtectedResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.ResourceOwnerPasswordResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.test.TestAccounts;
import org.cloudfoundry.identity.uaa.oauth.common.AuthenticationScheme;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.codec.Base64;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.springframework.util.StringUtils;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * UAA specific test account data externalized with
 * {@link TestProfileEnvironment}.
 *
 * @author Dave Syer
 * @author Joel D'sa
 *
 */
public final class UaaTestAccounts implements TestAccounts {
    private static final Logger logger = LoggerFactory.getLogger(UaaTestAccounts.class);

    static final String UAA_TEST_USERNAME = "uaa.test.username";
    static final String UAA_TEST_PASSWORD = "uaa.test.password";

    public static final String DEFAULT_PASSWORD = "koala";
    public static final String DEFAULT_USERNAME = "marissa";

    public static final String CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    public static final String CODE_CHALLENGE_METHOD_S256 = "S256";

    public static final String CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    private final Environment environment = TestProfileEnvironment.getEnvironment();
    private final UrlHelper server;
    private static final Map<String, OAuth2ProtectedResourceDetails> clientDetails = new HashMap<>();

    private UaaTestAccounts(UrlHelper server) {
        this.server = server;
    }

    public static UaaTestAccounts standard(UrlHelper server) {
        return new UaaTestAccounts(server);
    }

    @Override
    public String getUserName() {
        return environment.getProperty(UAA_TEST_USERNAME, DEFAULT_USERNAME);
    }

    @Override
    public String getPassword() {
        return environment.getProperty(UAA_TEST_PASSWORD, DEFAULT_PASSWORD);
    }

    @Override
    public String getEmail() {
        String value = getUserName();
        if (!value.contains("@")) {
            value = value + "@test.org";
        }
        return environment.getProperty("uaa.test.email", value);
    }

    public UaaUser getUserWithRandomID() {
        String id = UUID.randomUUID().toString();
        return new UaaUser(id, getUserName(), getPassword(), getEmail(),
                UaaAuthority.USER_AUTHORITIES, "Test", "User", new Date(), new Date(), OriginKeys.UAA, "externalId", true,
                IdentityZoneHolder.get().getId(), id, new Date());
    }

    @Override
    public String getAdminClientId() {
        return environment.getProperty("UAA_ADMIN_CLIENT_ID",
                environment.getProperty("oauth.clients.admin.id", "admin"));
    }

    @Override
    public String getAdminClientSecret() {
        return environment.getProperty("UAA_ADMIN_CLIENT_SECRET",
                environment.getProperty("oauth.clients.admin.secret", "adminsecret"));
    }

    /**
     * @return true if this Spring profile is enabled on the server
     */
    public boolean isProfileActive(String profile) {
        logger.debug("Checking for %s profile in: [%s]".formatted(profile, environment));
        return profile != null && environment.acceptsProfiles(Profiles.of(profile));
    }

    public String getAuthorizationHeader(String prefix, String defaultUsername, String defaultPassword) {
        String username = environment.getProperty(prefix + ".username", defaultUsername);
        String password = environment.getProperty(prefix + ".password", defaultPassword);
        return getAuthorizationHeader(username, password);
    }

    /**
     * Test method, preparing authorization header.
     * Same steps to spring security 5.5.x and newer, e.g.
     * https://github.com/spring-projects/spring-security/commit/e6c268add00bef40cc6f47d8963176f43b8a1de1
     * @param username client_id
     * @param password client_secret
     * @return OAuth2 encoded client_id and client_secret, e.g. https://datatracker.ietf.org/doc/html/rfc2617#section-2
     */
    public static String getAuthorizationHeader(String username, String password) {
        String credentials =
                "%s:%s".formatted(URLEncoder.encode(username, StandardCharsets.UTF_8), URLEncoder.encode(password, StandardCharsets.UTF_8));
        return "Basic %s".formatted(new String(Base64.encode(credentials.getBytes())));
    }

    public String getJsonCredentials(String prefix, String defaultUsername, String defaultPassword) {
        String username = environment.getProperty(prefix + ".username", defaultUsername);
        String password = environment.getProperty(prefix + ".password", defaultPassword);
        return getJsonCredentials(username, password);
    }

    public String getJsonCredentials(String username, String password) {
        return "{\"username\":\"%s\",\"password\":\"%s\"}".formatted(username, password);
    }

    public ClientCredentialsResourceDetails getAdminClientCredentialsResource() {
        return getClientCredentialsResource(new String[]{"clients.read", "clients.write", "clients.secret", "clients.admin"},
                getAdminClientId(), getAdminClientSecret());
    }

    public ClientCredentialsResourceDetails getClientCredentialsResource(String prefix, String defaultClientId,
            String defaultClientSecret) {
        return getClientCredentialsResource(prefix, new String[]{"scim.read", "scim.write", "password.write"},
                defaultClientId, defaultClientSecret);
    }

    public ClientCredentialsResourceDetails getClientCredentialsResource(String prefix, String[] scope,
            String defaultClientId, String defaultClientSecret) {
        if (clientDetails.containsKey(prefix)) {
            return (ClientCredentialsResourceDetails) clientDetails.get(prefix);
        }
        String clientId = environment.getProperty(prefix + ".id", defaultClientId);
        String clientSecret = environment.getProperty(prefix + ".secret", defaultClientSecret);
        ClientCredentialsResourceDetails resource = getClientCredentialsResource(scope, clientId, clientSecret);
        clientDetails.put(prefix, resource);
        return resource;
    }

    @Override
    public ClientCredentialsResourceDetails getClientCredentialsResource(String clientId, String clientSecret) {
        return getClientCredentialsResource(new String[]{"cloud_controller.read"}, clientId, clientSecret);
    }

    public ClientCredentialsResourceDetails getClientCredentialsResource(String[] scope, String clientId,
            String clientSecret) {
        ClientCredentialsResourceDetails resource = new ClientCredentialsResourceDetails();
        resource.setClientId(clientId);
        resource.setClientSecret(clientSecret);
        resource.setId(clientId);
        if (scope != null) {
            resource.setScope(Arrays.asList(scope));
        }
        resource.setClientAuthenticationScheme(AuthenticationScheme.header);
        resource.setAccessTokenUri(server.getAccessTokenUri());
        return resource;
    }

    public ImplicitResourceDetails getImplicitResource(String clientPrefix, String defaultClientId,
            String defaultRedirectUri) {
        ImplicitResourceDetails resource = new ImplicitResourceDetails();
        String clientId = environment.getProperty(clientPrefix + ".id", defaultClientId);
        resource.setClientId(clientId);
        resource.setId(clientId);
        resource.setClientAuthenticationScheme(AuthenticationScheme.header);
        resource.setAccessTokenUri(server.getAuthorizationUri());
        String redirectUri = environment.getProperty(clientPrefix + ".redirect-uri", defaultRedirectUri);
        resource.setPreEstablishedRedirectUri(redirectUri);
        return resource;
    }

    public ResourceOwnerPasswordResourceDetails getResourceOwnerPasswordResource(String clientPrefix,
            String defaultClientId, String defaultClientSecret, String username, String password) {
        return getResourceOwnerPasswordResource(new String[]{"cloud_controller.read", "openid", "password.write"},
                clientPrefix, defaultClientId, defaultClientSecret, username, password);
    }

    public ResourceOwnerPasswordResourceDetails getResourceOwnerPasswordResource(String[] scope, String clientPrefix,
            String defaultClientId, String defaultClientSecret, String username, String password) {
        String clientId = environment.getProperty(clientPrefix + ".id", defaultClientId);
        String clientSecret = environment.getProperty(clientPrefix + ".secret", defaultClientSecret);
        return getResourceOwnerPasswordResource(scope, clientId, clientSecret, username, password);
    }

    @Override
    public ResourceOwnerPasswordResourceDetails getResourceOwnerPasswordResource(String[] scope, String clientId,
            String clientSecret, String username, String password) {

        ResourceOwnerPasswordResourceDetails resource = new ResourceOwnerPasswordResourceDetails();
        resource.setClientId(clientId);
        resource.setClientSecret(clientSecret);
        resource.setId(clientId);
        resource.setScope(Arrays.asList(scope));
        resource.setUsername(username);
        resource.setPassword(password);
        resource.setClientAuthenticationScheme(AuthenticationScheme.header);
        resource.setAccessTokenUri(server.getAccessTokenUri());
        return resource;
    }

    public ClientDetails getClientDetails(String prefix, UaaClientDetails defaults) {
        String clientId = environment.getProperty(prefix + ".id", defaults.getClientId());
        String clientSecret = environment.getProperty(prefix + ".secret", defaults.getClientSecret());
        String resourceIds = environment.getProperty(prefix + ".resource-ids",
                StringUtils.collectionToCommaDelimitedString(defaults.getResourceIds()));
        String scopes = environment.getProperty(prefix + ".scope",
                StringUtils.collectionToCommaDelimitedString(defaults.getScope()));
        String grantTypes = environment.getProperty(prefix + ".authorized-grant-types",
                StringUtils.collectionToCommaDelimitedString(defaults.getAuthorizedGrantTypes()));
        String authorities = environment.getProperty(prefix + ".authorities",
                StringUtils.collectionToCommaDelimitedString(defaults.getAuthorities()));
        String redirectUris = environment.getProperty(prefix + ".redirect-uri",
                StringUtils.collectionToCommaDelimitedString(defaults.getRegisteredRedirectUri()));
        UaaClientDetails result = new UaaClientDetails(clientId, resourceIds, scopes, grantTypes, authorities,
                redirectUris);
        result.setClientSecret(clientSecret);
        return result;
    }

    @Override
    public ClientCredentialsResourceDetails getDefaultClientCredentialsResource() {
        return getClientCredentialsResource("oauth.clients.scim", "scim", "scimsecret");
    }

    @Override
    public ResourceOwnerPasswordResourceDetails getDefaultResourceOwnerPasswordResource() {
        return getResourceOwnerPasswordResource("oauth.clients.app", "app", "appclientsecret", getUserName(),
                getPassword());
    }

    @Override
    public ImplicitResourceDetails getDefaultImplicitResource() {
        return getImplicitResource("oauth.clients.cf", "cf", "http://localhost:8080/redirect/cf");
    }

    public AuthorizationCodeResourceDetails getDefaultAuthorizationCodeResource() {
        ResourceOwnerPasswordResourceDetails resource = getDefaultResourceOwnerPasswordResource();
        AuthorizationCodeResourceDetails result = new AuthorizationCodeResourceDetails();
        result.setAccessTokenUri(resource.getAccessTokenUri());
        result.setUserAuthorizationUri(resource.getAccessTokenUri().replace("/token", "/authorize"));
        result.setClientId(resource.getClientId());
        result.setClientSecret(resource.getClientSecret());
        String redirectUri = environment.getProperty("oauth.clients.app.redirect-uri", "http://localhost:8080/app/");
        result.setPreEstablishedRedirectUri(redirectUri);
        return result;
    }

    public String addUser(
            final JdbcTemplate jdbcTemplate,
            final String id,
            final String zoneId) {
        return addUser(
                jdbcTemplate,
                id,
                zoneId,
                OriginKeys.UAA
        );
    }

    public String addUser(
            final JdbcTemplate jdbcTemplate,
            final String id,
            final String zoneId,
            final String origin) {
        String username = id + "-testuser";
        jdbcTemplate.update("insert into users (id, username, password, email, identity_zone_id, origin) values (?,?,?,?,?,?)",
                id,
                username,
                "password",
                username + "@test.com",
                zoneId,
                origin);
        return id;
    }
}
