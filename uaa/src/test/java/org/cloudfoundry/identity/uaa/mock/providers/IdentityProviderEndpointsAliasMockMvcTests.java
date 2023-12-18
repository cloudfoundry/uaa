package org.cloudfoundry.identity.uaa.mock.providers;

import static java.util.Collections.singletonList;
import static java.util.Collections.singletonMap;
import static java.util.stream.Collectors.toList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;

import org.apache.commons.lang.RandomStringUtils;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.saml.BootstrapSamlIdentityProviderDataTests;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.util.StringUtils;

@DefaultTestContext
class IdentityProviderEndpointsAliasMockMvcTests {
    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private TestClient testClient;

    private IdentityZone customZone;
    private String adminToken;
    private String identityToken;

    @BeforeEach
    void setUp() throws Exception {
        adminToken = testClient.getClientCredentialsOAuthAccessToken(
                "admin",
                "adminsecret",
                "");
        identityToken = testClient.getClientCredentialsOAuthAccessToken(
                "identity",
                "identitysecret",
                "zones.write");
        customZone = MockMvcUtils.createZoneUsingWebRequest(mockMvc, identityToken);
    }

    @Nested
    class Create {
        @Test
        void testCreate_SuccessCase_MirrorFromUaaZoneToCustomZone() throws Exception {
            testCreate_SuccessCase(IdentityZone.getUaa(), customZone);
        }

        @Test
        void testCreate_SuccessCase_MirrorFromCustomZoneToUaaZone() throws Exception {
            testCreate_SuccessCase(customZone, IdentityZone.getUaa());
        }

        @Test
        void testCreate_ShouldReject_WhenIdzAndAliasZidAreEqual_Uaa() throws Exception {
            testCreate_ShouldReject_WhenIdzAndAliasZidAreEqual(IdentityZone.getUaa());
        }

        @Test
        void testCreate_ShouldReject_WhenIdzAndAliasZidAreEqual_Custom() throws Exception {
            testCreate_ShouldReject_WhenIdzAndAliasZidAreEqual(customZone);
        }

        @Test
        void testCreate_ShouldReject_WhenNeitherIdzNorAliasZidIsUaa() throws Exception {
            final IdentityZone otherCustomZone = MockMvcUtils.createZoneUsingWebRequest(mockMvc, identityToken);
            final IdentityProvider provider = buildIdpWithAliasProperties(
                    customZone.getId(),
                    null,
                    otherCustomZone.getId()
            );
            testCreate_ShouldReject(customZone, provider, HttpStatus.UNPROCESSABLE_ENTITY);
        }

        @Test
        void testCreate_ShouldReject_WhenAliasIdIsSet() throws Exception {
            testCreate_ShouldReject(
                    customZone,
                    buildIdpWithAliasProperties(
                            customZone.getId(),
                            UUID.randomUUID().toString(),
                            IdentityZone.getUaaZoneId()
                    ),
                    HttpStatus.UNPROCESSABLE_ENTITY
            );
        }

        @Test
        void testCreate_ShouldReject_WhenIdzReferencedInAliasZidDoesNotExist() throws Exception {
            final IdentityProvider provider = buildIdpWithAliasProperties(
                    IdentityZone.getUaaZoneId(),
                    null,
                    UUID.randomUUID().toString() // does not exist
            );
            final IdentityZone zone = IdentityZone.getUaa();
            testCreate_ShouldReject(zone, provider, HttpStatus.UNPROCESSABLE_ENTITY);
        }

        @Test
        void testCreate_ShouldReject_IdpWithOriginAlreadyExistsInAliasZone_CustomToUaa() throws Exception {
            testCreate_ShouldReject_IdpWithOriginAlreadyExistsInAliasZone(
                    customZone,
                    IdentityZone.getUaa()
            );
        }

        @Test
        void testCreate_ShouldReject_IdpWithOriginAlreadyExistsInAliasZone_UaaToCustom() throws Exception {
            testCreate_ShouldReject_IdpWithOriginAlreadyExistsInAliasZone(
                    IdentityZone.getUaa(),
                    customZone
            );
        }

        private void testCreate_ShouldReject_IdpWithOriginAlreadyExistsInAliasZone(
                final IdentityZone zone1,
                final IdentityZone zone2
        ) throws Exception {
            final String originKey = RandomStringUtils.randomAlphabetic(10);

            // create IdP with origin key in custom zone
            final IdentityProvider createdIdp1 = createIdp(
                    zone1,
                    buildIdpWithAliasProperties(zone1.getId(), null, null, originKey),
                    getAccessTokenForZone(zone1)
            );
            assertNotNull(createdIdp1);

            // then, create an IdP in the "uaa" zone with the same origin key that should be mirrored to the custom zone
            testCreate_ShouldReject(
                    zone2,
                    buildIdpWithAliasProperties(zone2.getId(), null, zone1.getId(), originKey),
                    HttpStatus.INTERNAL_SERVER_ERROR
            );
        }

        private void testCreate_SuccessCase(final IdentityZone zone1, final IdentityZone zone2) throws Exception {
            assertNotNull(zone1);
            assertNotNull(zone2);

            // build IdP in zone1 with aliasZid set to zone2
            final IdentityProvider provider = buildIdpWithAliasProperties(
                    IdentityZone.getUaa().getId(),
                    null,
                    zone2.getId()
            );

            // create IdP in zone1
            final IdentityProvider originalIdp = createIdp(zone1, provider, getAccessTokenForZone(zone1));
            assertNotNull(originalIdp);
            assertTrue(StringUtils.hasText(originalIdp.getAliasId()));
            assertTrue(StringUtils.hasText(originalIdp.getAliasZid()));
            assertEquals(zone2.getId(), originalIdp.getAliasZid());

            // read mirrored IdP from zone2
            final String accessTokenZone2 = getAccessTokenForZone(zone2);
            final IdentityProvider mirroredIdp = readIdpFromZone(zone2, originalIdp.getAliasId(), accessTokenZone2);
            assertIdpReferencesOtherIdp(mirroredIdp, originalIdp);
            assertOtherPropertiesAreEqual(originalIdp, mirroredIdp);

            // check if aliasId in first IdP is equal to the ID of the mirrored one
            assertEquals(mirroredIdp.getId(), originalIdp.getAliasId());
        }

        private void testCreate_ShouldReject_WhenIdzAndAliasZidAreEqual(final IdentityZone zone) throws Exception {
            final IdentityProvider provider = buildIdpWithAliasProperties(
                    zone.getId(),
                    null,
                    zone.getId()
            );
            testCreate_ShouldReject(zone, provider, HttpStatus.UNPROCESSABLE_ENTITY);
        }

        private void testCreate_ShouldReject(
                final IdentityZone zone,
                final IdentityProvider idp,
                final HttpStatus expectedStatus
        ) throws Exception {
            assertNotNull(zone);
            assertNotNull(idp);

            // create IdP in zone
            final MvcResult result = createIdpAndReturnResult(zone, idp, getAccessTokenForZone(zone));
            assertThat(result.getResponse().getStatus()).isEqualTo(expectedStatus.value());
        }
    }

    @Nested
    class Update {
        @Test
        void testUpdate_Success_MigrationScenario_CreateMirroredIdp_UaaToCustomZone() throws Exception {
            testUpdate_MigrationScenario_ShouldCreateMirroredIdp(IdentityZone.getUaa(), customZone);
        }

        @Test
        void testUpdate_Success_MigrationScenario_CreateMirroredIdp_CustomToUaaZone() throws Exception {
            testUpdate_MigrationScenario_ShouldCreateMirroredIdp(customZone, IdentityZone.getUaa());
        }

        @Test
        void testUpdate_Success_OtherPropertiesOfAlreadyMirroredIdpAreChanged() throws Exception {
            final IdentityZone zone1 = IdentityZone.getUaa();
            final IdentityZone zone2 = customZone;

            // create a mirrored IdP
            final IdentityProvider originalIdp = createMirroredIdp(zone1, zone2);

            // update other property
            final String newName = "new name";
            originalIdp.setName(newName);
            final IdentityProvider updatedOriginalIdp = updateIdp(zone1, originalIdp, getAccessTokenForZone(zone1));
            assertNotNull(updatedOriginalIdp);
            assertNotNull(updatedOriginalIdp.getAliasId());
            assertNotNull(updatedOriginalIdp.getAliasZid());
            assertEquals(zone2.getId(), updatedOriginalIdp.getAliasZid());

            assertNotNull(updatedOriginalIdp.getName());
            assertEquals(newName, updatedOriginalIdp.getName());

            // check if the change is propagated to the mirrored IdP
            final String accessTokenZone2 = getAccessTokenForZone(zone2);
            final IdentityProvider mirroredIdp = readIdpFromZone(
                    zone2,
                    updatedOriginalIdp.getAliasId(),
                    accessTokenZone2
            );
            assertIdpReferencesOtherIdp(mirroredIdp, updatedOriginalIdp);
            assertNotNull(mirroredIdp.getName());
            assertEquals(newName, mirroredIdp.getName());
        }

        @ParameterizedTest
        @MethodSource
        void testUpdate_ShouldReject_ChangingAliasPropertiesOfAlreadyMirroredIdp(
                final String newAliasId,
                final String newAliasZid
        ) throws Exception {
            final IdentityProvider originalIdp = createMirroredIdp(IdentityZone.getUaa(), customZone);
            originalIdp.setAliasId(newAliasId);
            originalIdp.setAliasZid(newAliasZid);
            updateIdp_ShouldReject(IdentityZone.getUaa(), originalIdp, HttpStatus.UNPROCESSABLE_ENTITY);
        }

        private static Stream<Arguments> testUpdate_ShouldReject_ChangingAliasPropertiesOfAlreadyMirroredIdp() {
            return Stream.of(null, "", "other").flatMap(aliasIdValue ->
                    Stream.of(null, "", "other").map(aliasZidValue ->
                            Arguments.of(aliasIdValue, aliasZidValue)
                    ));
        }

        @Test
        void testUpdate_ShouldReject_OnlyAliasIdSet_Uaa() throws Exception {
            testUpdate_ShouldReject_OnlyAliasIdSet(IdentityZone.getUaa());
        }

        @Test
        void testUpdate_ShouldReject_OnlyAliasIdSet_Custom() throws Exception {
            testUpdate_ShouldReject_OnlyAliasIdSet(customZone);
        }

        private void testUpdate_ShouldReject_OnlyAliasIdSet(final IdentityZone zone) throws Exception {
            final IdentityProvider idp = buildIdpWithAliasProperties(zone.getId(), null, null);
            final IdentityProvider createdProvider = createIdp(zone, idp, getAccessTokenForZone(zone));
            assertNull(createdProvider.getAliasZid());
            createdProvider.setAliasId(UUID.randomUUID().toString());
            updateIdp_ShouldReject(zone, createdProvider, HttpStatus.UNPROCESSABLE_ENTITY);
        }

        @Test
        void testUpdate_ShouldReject_IdpWithOriginKeyAlreadyPresentInOtherZone() throws Exception {
            final String originKey = RandomStringUtils.randomAlphabetic(10);

            final IdentityProvider existingProviderInCustomZone = buildIdpWithAliasProperties(
                    customZone.getId(),
                    null,
                    null,
                    originKey
            );
            createIdp(customZone, existingProviderInCustomZone, getAccessTokenForZone(customZone));

            final IdentityZone zone = IdentityZone.getUaa();
            final IdentityProvider idp = buildIdpWithAliasProperties(
                    IdentityZone.getUaa().getId(),
                    null,
                    null,
                    originKey // same origin key
            );
            // same origin key
            final IdentityProvider providerInUaaZone = createIdp(zone, idp, getAccessTokenForZone(zone));

            providerInUaaZone.setAliasZid(customZone.getId());
            updateIdp_ShouldReject(
                    IdentityZone.getUaa(),
                    providerInUaaZone,
                    HttpStatus.INTERNAL_SERVER_ERROR
            );
        }

        @Test
        void testUpdate_ShouldReject_IdpInCustomZoneMirroredToOtherCustomZone() throws Exception {
            final IdentityProvider idpInCustomZone = createIdp(
                    customZone,
                    buildIdpWithAliasProperties(customZone.getId(), null, null),
                    getAccessTokenForZone(customZone)
            );

            // try to mirror it to another custom zone
            idpInCustomZone.setAliasZid("not-uaa");
            updateIdp_ShouldReject(
                    customZone,
                    idpInCustomZone,
                    HttpStatus.UNPROCESSABLE_ENTITY
            );
        }

        private IdentityProvider createMirroredIdp(
                final IdentityZone zone1,
                final IdentityZone zone2
        ) throws Exception {
            final IdentityProvider provider = buildIdpWithAliasProperties(
                    zone1.getId(),
                    null,
                    zone2.getId()
            );
            return createIdp(zone1, provider, getAccessTokenForZone(zone1));
        }

        private void testUpdate_MigrationScenario_ShouldCreateMirroredIdp(
                final IdentityZone zone1,
                final IdentityZone zone2
        ) throws Exception {
            final String accessTokenForZone1 = getAccessTokenForZone(zone1);

            // create regular idp without alias properties in UAA zone
            final IdentityProvider existingIdpWithoutAlias = createIdp(
                    zone1,
                    buildIdpWithAliasProperties(zone1.getId(), null, null),
                    accessTokenForZone1
            );
            assertNotNull(existingIdpWithoutAlias);
            assertNotNull(existingIdpWithoutAlias.getId());

            // perform update: set Alias ZID
            existingIdpWithoutAlias.setAliasZid(zone2.getId());
            final IdentityProvider idpAfterUpdate = updateIdp(
                    zone1,
                    existingIdpWithoutAlias,
                    accessTokenForZone1
            );
            assertNotNull(idpAfterUpdate.getAliasId());
            assertNotNull(idpAfterUpdate.getAliasZid());
            assertEquals(zone2.getId(), idpAfterUpdate.getAliasZid());

            // read mirrored IdP through alias id in original IdP
            final String accessTokenForZone2 = getAccessTokenForZone(zone2);
            final IdentityProvider mirroredIdp = readIdpFromZone(
                    zone2,
                    idpAfterUpdate.getAliasId(),
                    accessTokenForZone2
            );
            assertIdpReferencesOtherIdp(mirroredIdp, idpAfterUpdate);
            assertOtherPropertiesAreEqual(idpAfterUpdate, mirroredIdp);
        }

        private IdentityProvider updateIdp(
                final IdentityZone zone,
                final IdentityProvider updatePayload,
                final String accessTokenForZone
        ) throws Exception {
            updatePayload.setIdentityZoneId(zone.getId());
            final MvcResult result = updateIdpAndReturnResult(zone, updatePayload, accessTokenForZone);
            assertEquals(HttpStatus.OK.value(), result.getResponse().getStatus());

            final IdentityProvider originalIdpAfterUpdate = JsonUtils.readValue(
                    result.getResponse().getContentAsString(),
                    IdentityProvider.class
            );
            assertNotNull(originalIdpAfterUpdate);
            assertNotNull(originalIdpAfterUpdate.getIdentityZoneId());
            assertEquals(zone.getId(), originalIdpAfterUpdate.getIdentityZoneId());
            return originalIdpAfterUpdate;
        }

        private MvcResult updateIdpAndReturnResult(
                final IdentityZone zone,
                final IdentityProvider updatePayload,
                final String accessTokenForZone
        ) throws Exception {
            final String id = updatePayload.getId();
            assertThat(id).isNotNull().isNotBlank();

            final MockHttpServletRequestBuilder updateRequestBuilder = put("/identity-providers/" + id)
                    .header("Authorization", "Bearer " + accessTokenForZone)
                    .header(IdentityZoneSwitchingFilter.HEADER, zone.getId())
                    .contentType(APPLICATION_JSON)
                    .content(JsonUtils.writeValueAsString(updatePayload));
            return mockMvc.perform(updateRequestBuilder).andReturn();
        }

        private void updateIdp_ShouldReject(
                final IdentityZone zone,
                final IdentityProvider idp,
                final HttpStatus expectedStatusCode
        ) throws Exception {
            final MvcResult result = updateIdpAndReturnResult(zone, idp, getAccessTokenForZone(zone));
            assertThat(result.getResponse().getStatus()).isEqualTo(expectedStatusCode.value());
        }
    }

    private void assertIdpReferencesOtherIdp(final IdentityProvider idp, final IdentityProvider referencedIdp) {
        assertNotNull(idp);
        assertNotNull(referencedIdp);
        assertTrue(StringUtils.hasText(idp.getAliasId()));
        assertEquals(referencedIdp.getId(), idp.getAliasId());
        assertTrue(StringUtils.hasText(idp.getAliasZid()));
        assertEquals(referencedIdp.getIdentityZoneId(), idp.getAliasZid());
    }

    private void assertOtherPropertiesAreEqual(final IdentityProvider idp, final IdentityProvider mirroredIdp) {
        // apart from the zone ID, the configs should be identical
        final SamlIdentityProviderDefinition originalIdpConfig = (SamlIdentityProviderDefinition) idp.getConfig();
        originalIdpConfig.setZoneId(null);
        final SamlIdentityProviderDefinition mirroredIdpConfig = (SamlIdentityProviderDefinition) mirroredIdp.getConfig();
        mirroredIdpConfig.setZoneId(null);
        assertEquals(originalIdpConfig, mirroredIdpConfig);

        // check if remaining properties are equal
        assertEquals(idp.getOriginKey(), mirroredIdp.getOriginKey());
        assertEquals(idp.getName(), mirroredIdp.getName());
        assertEquals(idp.getType(), mirroredIdp.getType());
    }

    private IdentityProvider createIdp(
            final IdentityZone zone,
            final IdentityProvider provider,
            final String accessTokenForZone
    ) throws Exception {
        final MvcResult createResult = createIdpAndReturnResult(zone, provider, accessTokenForZone);
        assertThat(createResult.getResponse().getStatus()).isEqualTo(HttpStatus.CREATED.value());
        return JsonUtils.readValue(
                createResult.getResponse().getContentAsString(),
                IdentityProvider.class
        );
    }

    private MvcResult createIdpAndReturnResult(
            final IdentityZone zone,
            final IdentityProvider idp,
            final String accessTokenForZone
    ) throws Exception {
        final MockHttpServletRequestBuilder createRequestBuilder = post("/identity-providers")
                .param("rawConfig", "true")
                .header("Authorization", "Bearer " + accessTokenForZone)
                .header(IdentityZoneSwitchingFilter.SUBDOMAIN_HEADER, zone.getSubdomain())
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(idp));
        return mockMvc.perform(createRequestBuilder).andReturn();
    }

    private String getAccessTokenForZone(final IdentityZone zone) throws Exception {
        final List<String> scopesForZone = getScopesForZone(zone, "admin");

        final ScimUser adminUser = MockMvcUtils.createAdminForZone(
                mockMvc,
                adminToken,
                String.join(",", scopesForZone),
                IdentityZone.getUaaZoneId()
        );
        final String accessToken = MockMvcUtils.getUserOAuthAccessTokenAuthCode(
                mockMvc,
                "identity",
                "identitysecret",
                adminUser.getId(),
                adminUser.getUserName(),
                adminUser.getPassword(),
                String.join(" ", scopesForZone),
                IdentityZone.getUaaZoneId(),
                TokenConstants.TokenFormat.JWT // use JWT for later checking if all scopes are present
        );

        // check if the token contains the expected scopes
        final Map<String, Object> claims = UaaTokenUtils.getClaims(accessToken);
        assertTrue(claims.containsKey("scope"));
        assertTrue(claims.get("scope") instanceof List<?>);
        final List<String> resultingScopes = (List<String>) claims.get("scope");
        assertThat(resultingScopes).hasSameElementsAs(scopesForZone);

        return accessToken;
    }

    private IdentityProvider readIdpFromZone(
            final IdentityZone zone,
            final String id,
            final String accessToken
    ) throws Exception {
        final MockHttpServletRequestBuilder getRequestBuilder = get("/identity-providers/" + id)
                .param("rawConfig", "true")
                .header(IdentityZoneSwitchingFilter.SUBDOMAIN_HEADER, zone.getSubdomain())
                .header("Authorization", "Bearer " + accessToken);
        final MvcResult getResult = mockMvc.perform(getRequestBuilder)
                .andExpect(status().isOk())
                .andReturn();
        return JsonUtils.readValue(
                getResult.getResponse().getContentAsString(),
                IdentityProvider.class
        );
    }

    private static List<String> getScopesForZone(final IdentityZone zone, final String... scopes) {
        return Stream.of(scopes).map(scope -> String.format("zones.%s.%s", zone.getId(), scope)).collect(toList());
    }

    private static IdentityProvider<SamlIdentityProviderDefinition> buildIdpWithAliasProperties(
            final String idzId,
            final String aliasId,
            final String aliasZid
    ) {
        final String originKey = RandomStringUtils.randomAlphabetic(8);
        return buildIdpWithAliasProperties(idzId, aliasId, aliasZid, originKey);
    }

    private static IdentityProvider<SamlIdentityProviderDefinition> buildIdpWithAliasProperties(
            final String idzId,
            final String aliasId,
            final String aliasZid,
            final String originKey
    ) {
        final String metadata = String.format(
                BootstrapSamlIdentityProviderDataTests.xmlWithoutID,
                "http://localhost:9999/metadata/" + originKey
        );
        final SamlIdentityProviderDefinition samlDefinition = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(metadata)
                .setLinkText("Test SAML Provider");
        samlDefinition.setEmailDomain(Arrays.asList("test.com", "test2.com"));
        samlDefinition.setExternalGroupsWhitelist(singletonList("value"));
        samlDefinition.setAttributeMappings(singletonMap("given_name", "first_name"));

        final IdentityProvider<SamlIdentityProviderDefinition> provider = new IdentityProvider<>();
        provider.setActive(true);
        provider.setName(originKey);
        provider.setIdentityZoneId(idzId);
        provider.setType(OriginKeys.SAML);
        provider.setOriginKey(originKey);
        provider.setConfig(samlDefinition);
        provider.setAliasId(aliasId);
        provider.setAliasZid(aliasZid);
        return provider;
    }
}
