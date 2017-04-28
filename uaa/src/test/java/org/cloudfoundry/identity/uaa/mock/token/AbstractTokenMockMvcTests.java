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

package org.cloudfoundry.identity.uaa.mock.token;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.oauth.UaaTokenServices;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableTokenProvisioning;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.MemberAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.zone.ClientServicesExtension;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.junit.Before;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.getClientCredentialsOAuthAccessToken;
import static org.junit.Assert.assertNull;
import static org.springframework.util.StringUtils.hasText;

public abstract class AbstractTokenMockMvcTests extends InjectedMockContextTest {

    public static final String SECRET = "secret";
    public static final String GRANT_TYPES = "password,implicit,client_credentials,authorization_code,refresh_token";
    public static final String TEST_REDIRECT_URI = "http://test.example.org/redirect";

    protected ClientServicesExtension clientDetailsService;
    protected JdbcScimUserProvisioning userProvisioning;
    protected JdbcScimGroupProvisioning groupProvisioning;
    protected JdbcScimGroupMembershipManager groupMembershipManager;
    protected UaaTokenServices tokenServices;
    protected Set<String> defaultAuthorities;

    protected IdentityZoneProvisioning identityZoneProvisioning;
    protected JdbcScimUserProvisioning jdbcScimUserProvisioning;
    protected IdentityProviderProvisioning identityProviderProvisioning;
    protected String adminToken;
    protected RevocableTokenProvisioning tokenProvisioning;
    protected RandomValueStringGenerator generator = new RandomValueStringGenerator();

    @Before
    public void setUpContext() throws Exception {
        clientDetailsService = (ClientServicesExtension) getWebApplicationContext().getBean("jdbcClientDetailsService");
        userProvisioning = (JdbcScimUserProvisioning) getWebApplicationContext().getBean("scimUserProvisioning");
        groupProvisioning = (JdbcScimGroupProvisioning) getWebApplicationContext().getBean("scimGroupProvisioning");
        groupMembershipManager = (JdbcScimGroupMembershipManager) getWebApplicationContext().getBean("groupMembershipManager");
        tokenServices = (UaaTokenServices) getWebApplicationContext().getBean("tokenServices");
        defaultAuthorities = (Set<String>) getWebApplicationContext().getBean("defaultUserAuthorities");
        identityZoneProvisioning = getWebApplicationContext().getBean(IdentityZoneProvisioning.class);
        jdbcScimUserProvisioning = getWebApplicationContext().getBean(JdbcScimUserProvisioning.class);
        identityProviderProvisioning = getWebApplicationContext().getBean(JdbcIdentityProviderProvisioning.class);
        IdentityZoneHolder.clear();

        adminToken =
            getClientCredentialsOAuthAccessToken(
                getMockMvc(),
                "admin",
                "adminsecret",
                "uaa.admin",
                null
            );
        tokenProvisioning = (RevocableTokenProvisioning) getWebApplicationContext().getBean("revocableTokenProvisioning");
    }

    public String setUpUserForPasswordGrant() throws Exception {
        String username = "testuser" + generator.generate();
        String userScopes = "uaa.user";
        ScimUser user = setUpUser(username, userScopes, OriginKeys.UAA, IdentityZone.getUaa().getId());
        ScimUserProvisioning provisioning = getWebApplicationContext().getBean(ScimUserProvisioning.class);
        ScimUser scimUser = provisioning.retrieve(user.getId());
        assertNull(scimUser.getLastLogonTime());
        assertNull(scimUser.getPreviousLogonTime());
        return username;
    }

    protected IdentityZone setupIdentityZone(String subdomain) {
        IdentityZone zone = new IdentityZone();
        zone.getConfig().getTokenPolicy().setKeys(Collections.singletonMap(subdomain+"_key", "key_for_"+subdomain));
        zone.setId(UUID.randomUUID().toString());
        zone.setName(subdomain);
        zone.setSubdomain(subdomain);
        zone.setDescription(subdomain);
        identityZoneProvisioning.create(zone);
        return zone;
    }

    protected IdentityProvider setupIdentityProvider() {
        return setupIdentityProvider(OriginKeys.UAA);
    }
    protected IdentityProvider setupIdentityProvider(String origin) {
        IdentityProvider defaultIdp = new IdentityProvider();
        defaultIdp.setName(origin);
        defaultIdp.setType(origin);
        defaultIdp.setOriginKey(origin);
        defaultIdp.setIdentityZoneId(IdentityZoneHolder.get().getId());
        return identityProviderProvisioning.create(defaultIdp);
    }

    protected BaseClientDetails setUpClients(String id, String authorities, String scopes, String grantTypes, Boolean autoapprove) {
        return setUpClients(id, authorities, scopes, grantTypes, autoapprove, null);
    }
    protected BaseClientDetails setUpClients(String id, String authorities, String scopes, String grantTypes, Boolean autoapprove, String redirectUri) {
        return setUpClients(id, authorities, scopes, grantTypes, autoapprove, redirectUri, null);
    }
    protected BaseClientDetails setUpClients(String id, String authorities, String scopes, String grantTypes, Boolean autoapprove, String redirectUri, List<String> allowedIdps) {
        return setUpClients(id, authorities, scopes, grantTypes, autoapprove, redirectUri, allowedIdps, -1);
    }
    protected BaseClientDetails setUpClients(String id, String authorities, String scopes, String grantTypes, Boolean autoapprove, String redirectUri, List<String> allowedIdps, int accessTokenValidity) {
        return setUpClients(id, authorities, scopes, grantTypes, autoapprove, redirectUri, allowedIdps, accessTokenValidity, null);
    }
    protected BaseClientDetails setUpClients(String id, String authorities, String scopes, String grantTypes, Boolean autoapprove, String redirectUri, List<String> allowedIdps, int accessTokenValidity, IdentityZone zone) {
        return setUpClients(id, authorities, scopes, grantTypes, autoapprove, redirectUri, allowedIdps, accessTokenValidity, zone, Collections.emptyMap());
    }
    protected BaseClientDetails setUpClients(String id, String authorities, String scopes, String grantTypes, Boolean autoapprove, String redirectUri, List<String> allowedIdps, int accessTokenValidity, IdentityZone zone, Map<String,Object> additionalInfo) {
        IdentityZone original = IdentityZoneHolder.get();
        if (zone!=null) {
            IdentityZoneHolder.set(zone);
        }
        BaseClientDetails c = new BaseClientDetails(id, "", scopes, grantTypes, authorities);
        if (!"implicit".equals(grantTypes)) {
            c.setClientSecret(SECRET);
        }
        c.setRegisteredRedirectUri(new HashSet<>(Arrays.asList(TEST_REDIRECT_URI)));
        c.setAutoApproveScopes(Collections.singleton(autoapprove.toString()));
        Map<String, Object> additional = new HashMap<>();
        if (allowedIdps!=null && !allowedIdps.isEmpty()) {
            additional.put(ClientConstants.ALLOWED_PROVIDERS, allowedIdps);
        }
        additional.putAll(additionalInfo);
        c.setAdditionalInformation(additional);
        if (hasText(redirectUri)) {
            c.setRegisteredRedirectUri(new HashSet<>(Arrays.asList(redirectUri)));
        }
        if (accessTokenValidity>0) {
            c.setAccessTokenValiditySeconds(accessTokenValidity);
        }
        try {
            clientDetailsService.addClientDetails(c);
            return (BaseClientDetails) clientDetailsService.loadClientByClientId(c.getClientId());
        } finally {
            IdentityZoneHolder.set(original);
        }
    }

    protected ScimUser setUpUser(String username, String scopes, String origin, String zoneId) {
        IdentityZone original = IdentityZoneHolder.get();
        ScimUser user = new ScimUser(null, username, "GivenName", "FamilyName");
        if (hasText(zoneId)) {
            IdentityZone zone = identityZoneProvisioning.retrieve(zoneId);
            IdentityZoneHolder.set(zone);
            user.setZoneId(zoneId);
        }
        try {

            user.setPassword(SECRET);
            ScimUser.Email email = new ScimUser.Email();
            email.setValue("test@test.org");
            email.setPrimary(true);
            user.setEmails(Arrays.asList(email));
            user.setVerified(true);
            user.setOrigin(origin);


            user = userProvisioning.createUser(user, SECRET);

            Set<String> scopeSet = StringUtils.commaDelimitedListToSet(scopes);
            Set<ScimGroup> groups = new HashSet<>();
            for (String scope : scopeSet) {
                ScimGroup g = createIfNotExist(scope, zoneId);
                groups.add(g);
                addMember(user, g);
            }

            return userProvisioning.retrieve(user.getId());
        } finally {
            IdentityZoneHolder.set(original);
        }
    }

    protected ScimUser syncGroups(ScimUser user) {
        if (user == null) {
            return user;
        }

        Set<ScimGroup> directGroups = groupMembershipManager.getGroupsWithMember(user.getId(), false);
        Set<ScimGroup> indirectGroups = groupMembershipManager.getGroupsWithMember(user.getId(), true);
        indirectGroups.removeAll(directGroups);
        Set<ScimUser.Group> groups = new HashSet<ScimUser.Group>();
        for (ScimGroup group : directGroups) {
            groups.add(new ScimUser.Group(group.getId(), group.getDisplayName(), ScimUser.Group.Type.DIRECT));
        }
        for (ScimGroup group : indirectGroups) {
            groups.add(new ScimUser.Group(group.getId(), group.getDisplayName(), ScimUser.Group.Type.INDIRECT));
        }

        user.setGroups(groups);
        return user;
    }

    protected ScimGroupMember addMember(ScimUser user, ScimGroup group) {
        ScimGroupMember gm = new ScimGroupMember(user.getId());
        try {
            return groupMembershipManager.addMember(group.getId(), gm);
        }catch (MemberAlreadyExistsException x) {
            return gm;
        }
    }

    protected ScimGroup createIfNotExist(String scope, String zoneId) {
        List<ScimGroup> exists = groupProvisioning.query("displayName eq \"" + scope + "\" and identity_zone_id eq \""+zoneId+"\"");
        if (exists.size() > 0) {
            return exists.get(0);
        } else {
            return groupProvisioning.create(new ScimGroup(null,scope,zoneId));
        }
    }
}
