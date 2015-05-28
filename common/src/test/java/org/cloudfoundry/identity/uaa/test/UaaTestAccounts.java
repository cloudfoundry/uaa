/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
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

import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.core.env.Environment;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.test.TestAccounts;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitResourceDetails;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.util.StringUtils;

/**
 * UAA specific test account data externalized with
 * {@link TestProfileEnvironment}.
 *
 * @author Dave Syer
 * @author Joel D'sa
 *
 */
public class UaaTestAccounts implements TestAccounts {

    /**
     * Default password for a user if strong passwords are required
     */
    private static final String DEFAULT_STRING_PASSWORD = "dr0wssaPH@ck";

    /**
     * Default password for a user if strong passwords are not required
     */
    public static final String DEFAULT_WEAK_PASSWORD = "koala";

    /**
     * Default username for a user account to use for testing
     */
    public static final String DEFAULT_USERNAME = "marissa";

    private static final Log logger = LogFactory.getLog(UaaTestAccounts.class);

    private Environment environment = TestProfileEnvironment.getEnvironment();

    private UrlHelper server;

    private static Map<String, OAuth2ProtectedResourceDetails> clientDetails = new HashMap<String, OAuth2ProtectedResourceDetails>();

    private UaaTestAccounts(UrlHelper server) {
        this.server = server;
    }

    public static UaaTestAccounts standard(UrlHelper server) {
        return new UaaTestAccounts(server);
    }

    @Override
    public String getUserName() {
        return environment.getProperty("uaa.test.username", DEFAULT_USERNAME);
    }

    @Override
    public String getPassword() {
        String defaultPassword = DEFAULT_WEAK_PASSWORD;
        if (environment.getActiveProfiles().length > 0 && (!isProfileActive("default"))) {
            // except in the default profile the password validator will block
            // "koala"
            defaultPassword = DEFAULT_STRING_PASSWORD;
        }
        return environment.getProperty("uaa.test.password", defaultPassword);
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
        UaaUser user = new UaaUser(id, getUserName(), "<N/A>", getEmail(),
                        UaaAuthority.USER_AUTHORITIES, "Test", "User", new Date(), new Date(), Origin.UAA, "externalId", true,
            IdentityZoneHolder.get().getId(), id);
        ReflectionTestUtils.setField(user, "password", getPassword());
        return user;
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
        logger.debug(String.format("Checking for %s profile in: [%s]", profile, environment));
        return profile != null && environment.acceptsProfiles(profile);
    }

    public String getVarzAuthorizationHeader() {
        return getAuthorizationHeader("varz", "varz", "varzclientsecret");
    }

    public String getAuthorizationHeader(String prefix, String defaultUsername, String defaultPassword) {
        String username = environment.getProperty(prefix + ".username", defaultUsername);
        String password = environment.getProperty(prefix + ".password", defaultPassword);
        return getAuthorizationHeader(username, password);
    }

    public String getAuthorizationHeader(String username, String password) {
        String credentials = String.format("%s:%s", username, password);
        return String.format("Basic %s", new String(Base64.encode(credentials.getBytes())));
    }

    public String getJsonCredentials(String prefix, String defaultUsername, String defaultPassword) {
        String username = environment.getProperty(prefix + ".username", defaultUsername);
        String password = environment.getProperty(prefix + ".password", defaultPassword);
        return getJsonCredentials(username, password);
    }

    public String getJsonCredentials(String username, String password) {
        String credentials = String.format("{\"username\":\"%s\",\"password\":\"%s\"}", username, password);
        return credentials;
    }

    public ClientCredentialsResourceDetails getAdminClientCredentialsResource() {
        return getClientCredentialsResource(new String[] { "clients.read", "clients.write", "clients.secret", "clients.admin" },
                        getAdminClientId(), getAdminClientSecret());
    }

    public ClientCredentialsResourceDetails getClientCredentialsResource(String prefix, String defaultClientId,
                    String defaultClientSecret) {
        return getClientCredentialsResource(prefix, new String[] { "scim.read", "scim.write", "password.write" },
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
        return getClientCredentialsResource(new String[] { "cloud_controller.read" }, clientId, clientSecret);
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
        return getResourceOwnerPasswordResource(new String[] { "cloud_controller.read", "openid", "password.write" },
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

    public ClientDetails getClientDetails(String prefix, BaseClientDetails defaults) {
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
        BaseClientDetails result = new BaseClientDetails(clientId, resourceIds, scopes, grantTypes, authorities,
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
        return getImplicitResource("oauth.clients.cf", "cf", "https://uaa.cloudfoundry.com/redirect/cf");
    }

    public AuthorizationCodeResourceDetails getDefaultAuthorizationCodeResource() {
        ResourceOwnerPasswordResourceDetails resource = getDefaultResourceOwnerPasswordResource();
        AuthorizationCodeResourceDetails result = new AuthorizationCodeResourceDetails();
        result.setAccessTokenUri(resource.getAccessTokenUri());
        result.setUserAuthorizationUri(resource.getAccessTokenUri().replace("/token", "/authorize"));
        result.setClientId(resource.getClientId());
        result.setClientSecret(resource.getClientSecret());
        String redirectUri = environment.getProperty("oauth.clients.app.redirect-uri", "http://anywhere.com");
        result.setPreEstablishedRedirectUri(redirectUri);
        return result;
    }
}
