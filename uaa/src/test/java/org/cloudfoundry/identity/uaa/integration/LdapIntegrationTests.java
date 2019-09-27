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
package org.cloudfoundry.identity.uaa.integration;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.security.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.doesSupportZoneDNS;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_ATTRIBUTE_PREFIX;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

public class LdapIntegrationTests {

    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    @Before
    public void setup() {
        String token = IntegrationTestUtils.getClientCredentialsToken(serverRunning.getBaseUrl(), "admin", "adminsecret");

        ScimGroup group = new ScimGroup(null, "zones.testzone1.admin", null);
        IntegrationTestUtils.createGroup(token, "", serverRunning.getBaseUrl(), group);
    }

    @After
    public void cleanup() {
        String token = IntegrationTestUtils.getClientCredentialsToken(serverRunning.getBaseUrl(), "admin", "adminsecret");
        String groupId = IntegrationTestUtils.getGroup(token, "", serverRunning.getBaseUrl(), "zones.testzone1.admin").getId();
        IntegrationTestUtils.deleteGroup(token, "", serverRunning.getBaseUrl(), groupId);
    }

    @Test
    public void test_LDAP_Custom_User_Attributes_In_ID_Token() {
        assertTrue("Expected testzone1.localhost and testzone2.localhost to resolve to 127.0.0.1", doesSupportZoneDNS());

        final String COST_CENTER = "costCenter";
        final String COST_CENTERS = "costCenters";
        final String DENVER_CO = "Denver,CO";
        final String MANAGER = "uaaManager";
        final String MANAGERS = "managers";
        final String JOHN_THE_SLOTH = "John the Sloth";
        final String KARI_THE_ANT_EATER = "Kari the Ant Eater";

        String baseUrl = serverRunning.getBaseUrl();

        String zoneId = "testzone1";
        String zoneUrl = baseUrl.replace("localhost", "testzone1.localhost");

        //identity client token
        RestTemplate identityClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret")
        );
        //admin client token - to create users
        RestTemplate adminClient = IntegrationTestUtils.getClientCredentialsTemplate(
            IntegrationTestUtils.getClientCredentialsResource(baseUrl, new String[0], "admin", "adminsecret")
        );
        //create the zone

        IntegrationTestUtils.createZoneOrUpdateSubdomain(identityClient, baseUrl, zoneId, zoneId, null);

        //create a zone admin user
        String email = new RandomValueStringGenerator().generate() +"@samltesting.org";
        ScimUser user = IntegrationTestUtils.createUser(adminClient, baseUrl,email ,"firstname", "lastname", email, true);
        String groupId = IntegrationTestUtils.findGroupId(
          adminClient, serverRunning.getBaseUrl(), String.format("zones.%s.admin", zoneId)
        );
        IntegrationTestUtils.addMemberToGroup(adminClient, serverRunning.getBaseUrl(), user.getId(), groupId);

        //get the zone admin token
        String zoneAdminToken =
            IntegrationTestUtils.getAccessTokenByAuthCode(serverRunning,
                                                           UaaTestAccounts.standard(serverRunning),
                                                           "identity",
                                                           "identitysecret",
                                                           email,
                                                           "secr3T");

        LdapIdentityProviderDefinition ldapIdentityProviderDefinition = LdapIdentityProviderDefinition.searchAndBindMapGroupToScopes(
            "ldap://localhost:389/",
            "cn=admin,dc=test,dc=com",
            "password",
            "dc=test,dc=com",
            "cn={0}",
            "ou=scopes,dc=test,dc=com",
            "member={0}",
            "mail",
            null,
            false,
            true,
            true,
            100,
            true);
        ldapIdentityProviderDefinition.addAttributeMapping(USER_ATTRIBUTE_PREFIX+COST_CENTERS, COST_CENTER);
        ldapIdentityProviderDefinition.addAttributeMapping(USER_ATTRIBUTE_PREFIX+MANAGERS, MANAGER);
        ldapIdentityProviderDefinition.addWhiteListedGroup("marissaniner");
        ldapIdentityProviderDefinition.addWhiteListedGroup("marissaniner2");


        IdentityProvider provider = new IdentityProvider();
        provider.setIdentityZoneId(zoneId);
        provider.setType(OriginKeys.LDAP);
        provider.setActive(true);
        provider.setConfig(ldapIdentityProviderDefinition);
        provider.setOriginKey(OriginKeys.LDAP);
        provider.setName("simplesamlphp for uaa");
        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken,baseUrl,provider);
        assertNotNull(provider.getId());

        assertEquals(OriginKeys.LDAP, provider.getOriginKey());

        List<String> idps = Collections.singletonList(provider.getOriginKey());

        String adminClientInZone = new RandomValueStringGenerator().generate();
        BaseClientDetails clientDetails = new BaseClientDetails(adminClientInZone, null, "openid,user_attributes,roles", "password,authorization_code,client_credentials", "uaa.admin,scim.read,scim.write,uaa.resource", zoneUrl);
        clientDetails.setClientSecret("secret");
        clientDetails.setAutoApproveScopes(Collections.singleton("true"));
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, idps);

        clientDetails = IntegrationTestUtils.createClientAsZoneAdmin(zoneAdminToken, baseUrl, zoneId, clientDetails);
        clientDetails.setClientSecret("secret");


        String idToken =
            (String) IntegrationTestUtils.getPasswordToken(zoneUrl,
                                                           clientDetails.getClientId(),
                                                           clientDetails.getClientSecret(),
                                                           "marissa9",
                                                           "ldap9",
                                                           "openid user_attributes roles")
                .get("id_token");

        assertNotNull(idToken);

        Jwt idTokenClaims = JwtHelper.decode(idToken);
        Map<String, Object> claims = JsonUtils.readValue(idTokenClaims.getClaims(), new TypeReference<Map<String, Object>>() {});

        assertNotNull(claims.get(ClaimConstants.USER_ATTRIBUTES));
        Map<String,List<String>> userAttributes = (Map<String, List<String>>) claims.get(ClaimConstants.USER_ATTRIBUTES);
        assertThat(userAttributes.get(COST_CENTERS), containsInAnyOrder(DENVER_CO));
        assertThat(userAttributes.get(MANAGERS), containsInAnyOrder(JOHN_THE_SLOTH, KARI_THE_ANT_EATER));


        assertNotNull(claims.get(ClaimConstants.ROLES));
        List<String> roles = (List<String>) claims.get(ClaimConstants.ROLES);
        assertThat(roles, containsInAnyOrder("marissaniner", "marissaniner2"));

        //no user_attribute scope provided
        idToken =
            (String) IntegrationTestUtils.getPasswordToken(zoneUrl,
                                                           clientDetails.getClientId(),
                                                           clientDetails.getClientSecret(),
                                                           "marissa9",
                                                           "ldap9",
                                                           "openid")
                .get("id_token");

        assertNotNull(idToken);

        idTokenClaims = JwtHelper.decode(idToken);
        claims = JsonUtils.readValue(idTokenClaims.getClaims(), new TypeReference<Map<String, Object>>() {});
        assertNull(claims.get(ClaimConstants.USER_ATTRIBUTES));
        assertNull(claims.get(ClaimConstants.ROLES));


        String username = "\u7433\u8D3A";
        idToken =
            (String) IntegrationTestUtils.getPasswordToken(zoneUrl,
                                                           clientDetails.getClientId(),
                                                           clientDetails.getClientSecret(),
                                                           username,
                                                           "koala",
                                                           "openid")
                .get("id_token");

        assertNotNull(idToken);
    }

    protected boolean isLdapEnabled() {
        String profile = System.getProperty("spring.profiles.active","");
        return profile.contains(OriginKeys.LDAP);
    }

}
