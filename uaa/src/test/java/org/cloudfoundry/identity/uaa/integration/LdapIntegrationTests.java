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
import org.cloudfoundry.identity.uaa.ServerRunningExtension;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils.doesSupportZoneDNS;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_ATTRIBUTE_PREFIX;

class LdapIntegrationTests {
    @RegisterExtension
    private static final ServerRunningExtension serverRunning = ServerRunningExtension.connect();

    @BeforeEach
    void setup() {
        String token = IntegrationTestUtils.getClientCredentialsToken(serverRunning.getBaseUrl(), "admin", "adminsecret");

        IntegrationTestUtils.ensureGroupExists(token, "", serverRunning.getBaseUrl(), "zones.testzone1.admin");
    }

    @AfterEach
    void cleanup() {
        String token = IntegrationTestUtils.getClientCredentialsToken(serverRunning.getBaseUrl(), "admin", "adminsecret");
        String groupId = IntegrationTestUtils.getGroup(token, "", serverRunning.getBaseUrl(), "zones.testzone1.admin").getId();
        IntegrationTestUtils.deleteGroup(token, "", serverRunning.getBaseUrl(), groupId);
    }

    @Test
    void ldap_custom_user_attributes_in_id_token() {
        assertThat(doesSupportZoneDNS()).as("Expected testzone1.localhost and testzone2.localhost to resolve to 127.0.0.1").isTrue();

        final String costCenter = "costCenter";
        final String costCenters = "costCenters";
        final String denverCo = "Denver,CO";
        final String manager = "uaaManager";
        final String managers = "managers";
        final String johnTheSloth = "John the Sloth";
        final String kariTheAntEater = "Kari the Ant Eater";

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
        String email = new RandomValueStringGenerator().generate() + "@samltesting.org";
        ScimUser user = IntegrationTestUtils.createUser(adminClient, baseUrl, email, "firstname", "lastname", email, true);
        String groupId = IntegrationTestUtils.findGroupId(
                adminClient, serverRunning.getBaseUrl(), "zones.%s.admin".formatted(zoneId)
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
        ldapIdentityProviderDefinition.addAttributeMapping(USER_ATTRIBUTE_PREFIX + costCenters, costCenter);
        ldapIdentityProviderDefinition.addAttributeMapping(USER_ATTRIBUTE_PREFIX + managers, manager);
        ldapIdentityProviderDefinition.addWhiteListedGroup("marissaniner");
        ldapIdentityProviderDefinition.addWhiteListedGroup("marissaniner2");

        IdentityProvider<LdapIdentityProviderDefinition> provider = new IdentityProvider<>();
        provider.setIdentityZoneId(zoneId);
        provider.setType(OriginKeys.LDAP);
        provider.setActive(true);
        provider.setConfig(ldapIdentityProviderDefinition);
        provider.setOriginKey(OriginKeys.LDAP);
        provider.setName("simplesamlphp for uaa");
        provider = IntegrationTestUtils.createOrUpdateProvider(zoneAdminToken, baseUrl, provider);
        assertThat(provider.getId()).isNotNull();

        assertThat(provider.getOriginKey()).isEqualTo(OriginKeys.LDAP);

        List<String> idps = Collections.singletonList(provider.getOriginKey());

        String adminClientInZone = new RandomValueStringGenerator().generate();
        UaaClientDetails clientDetails = new UaaClientDetails(adminClientInZone, null, "openid,user_attributes,roles", "password,authorization_code,client_credentials", "uaa.admin,scim.read,scim.write,uaa.resource", zoneUrl);
        clientDetails.setClientSecret("secret");
        clientDetails.setAutoApproveScopes(Collections.singleton("true"));
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, idps);

        clientDetails = IntegrationTestUtils.createClientAsZoneAdmin(zoneAdminToken, baseUrl, zoneId, clientDetails);
        clientDetails.setClientSecret("secret");

        String idToken = (String) IntegrationTestUtils.getPasswordToken(zoneUrl,
                        clientDetails.getClientId(),
                        clientDetails.getClientSecret(),
                        "marissa9",
                        "ldap9",
                        "openid user_attributes roles")
                .get("id_token");

        assertThat(idToken).isNotNull();

        Jwt idTokenClaims = JwtHelper.decode(idToken);
        Map<String, Object> claims = JsonUtils.readValue(idTokenClaims.getClaims(), new TypeReference<>() {
        });

        assertThat(claims).containsKey(ClaimConstants.USER_ATTRIBUTES);
        Map<String, List<String>> userAttributes = (Map<String, List<String>>) claims.get(ClaimConstants.USER_ATTRIBUTES);
        assertThat(userAttributes.get(costCenters)).contains(denverCo);
        assertThat(userAttributes.get(managers)).contains(johnTheSloth, kariTheAntEater);

        assertThat(claims).containsKey(ClaimConstants.ROLES);
        List<String> roles = (List<String>) claims.get(ClaimConstants.ROLES);
        assertThat(roles).contains("marissaniner", "marissaniner2");

        //no user_attribute scope provided
        idToken =
                (String) IntegrationTestUtils.getPasswordToken(zoneUrl,
                                clientDetails.getClientId(),
                                clientDetails.getClientSecret(),
                                "marissa9",
                                "ldap9",
                                "openid")
                        .get("id_token");

        assertThat(idToken).isNotNull();

        idTokenClaims = JwtHelper.decode(idToken);
        claims = JsonUtils.readValue(idTokenClaims.getClaims(), new TypeReference<>() {
        });
        assertThat(claims).doesNotContainKey(ClaimConstants.USER_ATTRIBUTES)
                .doesNotContainKey(ClaimConstants.ROLES);

        String username = "琳贺";
        idToken =
                (String) IntegrationTestUtils.getPasswordToken(zoneUrl,
                                clientDetails.getClientId(),
                                clientDetails.getClientSecret(),
                                username,
                                "koala",
                                "openid")
                        .get("id_token");

        assertThat(idToken).isNotNull();
    }
}
