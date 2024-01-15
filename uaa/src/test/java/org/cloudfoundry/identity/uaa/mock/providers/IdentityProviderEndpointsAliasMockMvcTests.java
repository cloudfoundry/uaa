package org.cloudfoundry.identity.uaa.mock.providers;

import static java.util.Collections.singletonList;
import static java.util.Collections.singletonMap;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toSet;
import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.SAML;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.util.StringUtils.hasText;

import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.provider.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.saml.BootstrapSamlIdentityProviderDataTests;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
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
import org.springframework.web.context.WebApplicationContext;

import com.fasterxml.jackson.core.type.TypeReference;

/**
 * Tests regarding the handling of "aliasId" and "aliasZid" properties of identity providers.
 */
@DefaultTestContext
class IdentityProviderEndpointsAliasMockMvcTests {
    private static final AlphanumericRandomValueStringGenerator RANDOM_STRING_GENERATOR = new AlphanumericRandomValueStringGenerator(8);

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private TestClient testClient;

    @Autowired
    private WebApplicationContext webApplicationContext;

    private final Map<String, String> accessTokenCache = new HashMap<>();
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
        void shouldAccept_CreateAliasIdp_UaaToCustomZone() throws Exception {
            shouldAccept_CreateAliasIdp(IdentityZone.getUaa(), customZone);
        }

        @Test
        void shouldAccept_CreateAliasIdp_CustomToUaaZone() throws Exception {
            shouldAccept_CreateAliasIdp(customZone, IdentityZone.getUaa());
        }

        private void shouldAccept_CreateAliasIdp(final IdentityZone zone1, final IdentityZone zone2) throws Exception {
            // build IdP in zone1 with aliasZid set to zone2
            final IdentityProvider<?> provider = buildSamlIdpWithAliasProperties(zone1.getId(), null, zone2.getId());

            // create IdP in zone1
            final IdentityProvider<?> originalIdp = createIdp(zone1, provider);
            assertThat(originalIdp).isNotNull();
            assertThat(originalIdp.getAliasId()).isNotBlank();
            assertThat(originalIdp.getAliasZid()).isNotBlank().isEqualTo(zone2.getId());

            // read alias IdP from zone2
            final String id = originalIdp.getAliasId();
            final Optional<IdentityProvider<?>> aliasIdp = readIdpFromZoneIfExists(zone2.getId(), id);
            assertThat(aliasIdp).isPresent();
            assertIdpReferencesOtherIdp(aliasIdp.get(), originalIdp);
            assertOtherPropertiesAreEqual(originalIdp, aliasIdp.get());

            // check if aliasId in first IdP is equal to the ID of the alias IdP
            assertThat(aliasIdp.get().getId()).isEqualTo(originalIdp.getAliasId());
        }

        @Test
        void shouldReject_IdzAndAliasZidAreEqual_UaaZone() throws Exception {
            shouldReject_IdzAndAliasZidAreEqual(IdentityZone.getUaa());
        }

        @Test
        void shouldReject_IdzAndAliasZidAreEqual_CustomZone() throws Exception {
            shouldReject_IdzAndAliasZidAreEqual(customZone);
        }

        private void shouldReject_IdzAndAliasZidAreEqual(final IdentityZone zone) throws Exception {
            final IdentityProvider<?> idp = buildSamlIdpWithAliasProperties(zone.getId(), null, zone.getId());
            shouldRejectCreation(zone, idp, HttpStatus.UNPROCESSABLE_ENTITY);
        }

        @Test
        void shouldReject_AliasNotSupportedForIdpType_UaaToCustomZone() throws Exception {
            shouldReject_AliasNotSupportedForIdpType(IdentityZone.getUaa(), customZone);
        }

        @Test
        void shouldReject_AliasNotSupportedForIdpType_CustomToUaaZone() throws Exception {
            shouldReject_AliasNotSupportedForIdpType(customZone, IdentityZone.getUaa());
        }

        private void shouldReject_AliasNotSupportedForIdpType(final IdentityZone zone1, final IdentityZone zone2) throws Exception {
            final IdentityProvider<?> uaaIdp = buildUaaIdpWithAliasProperties(zone1.getId(), null, zone2.getId());
            shouldRejectCreation(zone1, uaaIdp, HttpStatus.UNPROCESSABLE_ENTITY);
        }

        @Test
        void shouldReject_NeitherIdzNorAliasZidIsUaa() throws Exception {
            final IdentityZone otherCustomZone = MockMvcUtils.createZoneUsingWebRequest(mockMvc, identityToken);
            final IdentityProvider<?> idp = buildSamlIdpWithAliasProperties(customZone.getId(), null, otherCustomZone.getId());
            shouldRejectCreation(customZone, idp, HttpStatus.UNPROCESSABLE_ENTITY);
        }

        @Test
        void shouldReject_AliasIdIsSet() throws Exception {
            final String aliasId = UUID.randomUUID().toString();
            final IdentityProvider<?> idp = buildSamlIdpWithAliasProperties(customZone.getId(), aliasId, IdentityZone.getUaaZoneId());
            shouldRejectCreation(customZone, idp, HttpStatus.UNPROCESSABLE_ENTITY);
        }

        @Test
        void shouldReject_IdzReferencedInAliasZidDoesNotExist() throws Exception {
            final IdentityProvider<?> provider = buildSamlIdpWithAliasProperties(
                    IdentityZone.getUaaZoneId(),
                    null,
                    UUID.randomUUID().toString() // does not exist
            );
            shouldRejectCreation(IdentityZone.getUaa(), provider, HttpStatus.UNPROCESSABLE_ENTITY);
        }

        @Test
        void shouldReject_IdpWithOriginAlreadyExistsInAliasZone_CustomToUaaZone() throws Exception {
            shouldReject_IdpWithOriginAlreadyExistsInAliasZone(customZone, IdentityZone.getUaa());
        }

        @Test
        void shouldReject_IdpWithOriginAlreadyExistsInAliasZone_UaaToCustomZone() throws Exception {
            shouldReject_IdpWithOriginAlreadyExistsInAliasZone(IdentityZone.getUaa(), customZone);
        }

        private void shouldReject_IdpWithOriginAlreadyExistsInAliasZone(final IdentityZone zone1, final IdentityZone zone2) throws Exception {
            // create IdP with origin key in zone 1
            final IdentityProvider<?> createdIdp1 = createIdp(
                    zone1,
                    buildSamlIdpWithAliasProperties(zone1.getId(), null, null)
            );
            assertThat(createdIdp1).isNotNull();

            // then, create an IdP in zone 2 with the same origin key for which an alias in zone 1 should be created -> should fail
            shouldRejectCreation(
                    zone2,
                    buildIdpWithAliasProperties(zone2.getId(), null, zone1.getId(), createdIdp1.getOriginKey(), SAML),
                    HttpStatus.CONFLICT
            );
        }

        private void shouldRejectCreation(final IdentityZone zone, final IdentityProvider<?> idp, final HttpStatus expectedStatus) throws Exception {
            assertThat(expectedStatus.isError()).isTrue();

            final MvcResult result = createIdpAndReturnResult(zone, idp);
            assertThat(result.getResponse().getStatus()).isEqualTo(expectedStatus.value());

            // after the failed creation, the IdP must not exist
            final List<IdentityProvider<?>> idpsInZoneAfterFailedCreation = readAllIdpsInZone(zone);
            assertThat(idpsInZoneAfterFailedCreation.stream().map(IdentityProvider::getOriginKey).collect(toSet()))
                    .doesNotContain(idp.getOriginKey());
        }
    }

    @Nested
    class Update {
        @Test
        void shouldAccept_ShouldCreateAliasIdp_UaaToCustomZone() throws Exception {
            shouldAccept_ShouldCreateAliasIdp(IdentityZone.getUaa(), customZone);
        }

        @Test
        void shouldAccept_ShouldCreateAliasIdp_CustomToUaaZone() throws Exception {
            shouldAccept_ShouldCreateAliasIdp(customZone, IdentityZone.getUaa());
        }

        private void shouldAccept_ShouldCreateAliasIdp(final IdentityZone zone1, final IdentityZone zone2) throws Exception {
            // create regular idp without alias properties in zone 1
            final IdentityProvider<?> existingIdpWithoutAlias = createIdp(
                    zone1,
                    buildSamlIdpWithAliasProperties(zone1.getId(), null, null)
            );
            assertThat(existingIdpWithoutAlias).isNotNull();
            assertThat(existingIdpWithoutAlias.getId()).isNotBlank();

            // perform update: set Alias ZID
            existingIdpWithoutAlias.setAliasZid(zone2.getId());
            final IdentityProvider<?> idpAfterUpdate = updateIdp(zone1, existingIdpWithoutAlias);
            assertThat(idpAfterUpdate.getAliasId()).isNotBlank();
            assertThat(idpAfterUpdate.getAliasZid()).isNotBlank();
            assertThat(zone2.getId()).isEqualTo(idpAfterUpdate.getAliasZid());

            // read alias IdP through alias id in original IdP
            final String id = idpAfterUpdate.getAliasId();
            final Optional<IdentityProvider<?>> idp = readIdpFromZoneIfExists(zone2.getId(), id);
            assertThat(idp).isPresent();
            final IdentityProvider<?> aliasIdp = idp.get();
            assertIdpReferencesOtherIdp(aliasIdp, idpAfterUpdate);
            assertOtherPropertiesAreEqual(idpAfterUpdate, aliasIdp);
        }

        @Test
        void shouldAccept_OtherPropertiesOfIdpWithAliasAreChanged_UaaToCustomZone() throws Exception {
            shouldAccept_OtherPropertiesOfIdpWithAliasAreChanged(IdentityZone.getUaa(), customZone);
        }

        @Test
        void shouldAccept_OtherPropertiesOfIdpWithAliasAreChanged_CustomToUaaZone() throws Exception {
            shouldAccept_OtherPropertiesOfIdpWithAliasAreChanged(customZone, IdentityZone.getUaa());
        }

        private void shouldAccept_OtherPropertiesOfIdpWithAliasAreChanged(final IdentityZone zone1, final IdentityZone zone2) throws Exception {
            // create an IdP with an alias
            final IdentityProvider<?> originalIdp = createIdpWithAlias(zone1, zone2);

            // update other property
            final String newName = "new name";
            originalIdp.setName(newName);
            final IdentityProvider<?> updatedOriginalIdp = updateIdp(zone1, originalIdp);
            assertThat(updatedOriginalIdp).isNotNull();
            assertThat(updatedOriginalIdp.getAliasId()).isNotBlank();
            assertThat(updatedOriginalIdp.getAliasZid()).isNotBlank();
            assertThat(updatedOriginalIdp.getAliasZid()).isEqualTo(zone2.getId());
            assertThat(updatedOriginalIdp.getName()).isNotBlank().isEqualTo(newName);

            // check if the change is propagated to the alias IdP
            final String id = updatedOriginalIdp.getAliasId();
            final Optional<IdentityProvider<?>> aliasIdp = readIdpFromZoneIfExists(zone2.getId(), id);
            assertThat(aliasIdp).isPresent();
            assertIdpReferencesOtherIdp(aliasIdp.get(), updatedOriginalIdp);
            assertThat(aliasIdp.get().getName()).isNotBlank().isEqualTo(newName);
        }

        @Test
        void shouldAccept_ReferencedIdpNotExisting_ShouldCreateNewAliasIdp_UaaToCustomZone() throws Exception {
            shouldAccept_ReferencedIdpNotExisting_ShouldCreateNewAliasIdp(IdentityZone.getUaa(), customZone);
        }

        @Test
        void shouldAccept_ReferencedIdpNotExisting_ShouldCreateNewAliasIdp_CustomToUaaZone() throws Exception {
            shouldAccept_ReferencedIdpNotExisting_ShouldCreateNewAliasIdp(customZone, IdentityZone.getUaa());
        }

        private void shouldAccept_ReferencedIdpNotExisting_ShouldCreateNewAliasIdp(final IdentityZone zone1, final IdentityZone zone2) throws Exception {
            final IdentityProvider<?> idp = createIdpWithAlias(zone1, zone2);

            // delete the alias IdP directly in the DB -> after that, there is a dangling reference
            deleteIdpViaDb(idp.getOriginKey(), zone2.getId());

            // update some other property on the original IdP
            idp.setName("some-new-name");
            final IdentityProvider<?> updatedIdp = updateIdp(zone1, idp);
            assertThat(updatedIdp.getAliasId()).isNotBlank().isNotEqualTo(idp.getAliasId());
            assertThat(updatedIdp.getAliasZid()).isNotBlank().isEqualTo(idp.getAliasZid());

            // check if the new alias IdP is present and has the correct properties
            final String id = updatedIdp.getAliasId();
            final Optional<IdentityProvider<?>> aliasIdp = readIdpFromZoneIfExists(zone2.getId(), id);
            assertThat(aliasIdp).isPresent();
            assertIdpReferencesOtherIdp(updatedIdp, aliasIdp.get());
            assertOtherPropertiesAreEqual(updatedIdp, aliasIdp.get());
        }

        @ParameterizedTest
        @MethodSource("shouldReject_ChangingAliasPropertiesOfIdpWithAlias")
        void shouldReject_ChangingAliasPropertiesOfIdpWithAlias_UaaToCustomZone(final String newAliasId, final String newAliasZid) throws Exception {
            shouldReject_ChangingAliasPropertiesOfIdpWithAlias(newAliasId, newAliasZid, IdentityZone.getUaa(), customZone);
        }

        @ParameterizedTest
        @MethodSource("shouldReject_ChangingAliasPropertiesOfIdpWithAlias")
        void shouldReject_ChangingAliasPropertiesOfIdpWithAlias_CustomToUaaZone(final String newAliasId, final String newAliasZid) throws Exception {
            shouldReject_ChangingAliasPropertiesOfIdpWithAlias(newAliasId, newAliasZid, customZone, IdentityZone.getUaa());
        }

        private void shouldReject_ChangingAliasPropertiesOfIdpWithAlias(
                final String newAliasId,
                final String newAliasZid,
                final IdentityZone zone1,
                final IdentityZone zone2
        ) throws Exception {
            final IdentityProvider<?> originalIdp = createIdpWithAlias(zone1, zone2);
            originalIdp.setAliasId(newAliasId);
            originalIdp.setAliasZid(newAliasZid);
            shouldRejectUpdate(zone1, originalIdp, HttpStatus.UNPROCESSABLE_ENTITY);
        }

        private static Stream<Arguments> shouldReject_ChangingAliasPropertiesOfIdpWithAlias() {
            return Stream.of(null, "", "other").flatMap(aliasIdValue ->
                    Stream.of(null, "", "other").map(aliasZidValue ->
                            Arguments.of(aliasIdValue, aliasZidValue)
                    ));
        }

        @Test
        void shouldReject_OnlyAliasIdSet_UaaZone() throws Exception {
            shouldReject_OnlyAliasIdSet(IdentityZone.getUaa());
        }

        @Test
        void shouldReject_OnlyAliasIdSet_CustomZone() throws Exception {
            shouldReject_OnlyAliasIdSet(customZone);
        }

        private void shouldReject_OnlyAliasIdSet(final IdentityZone zone) throws Exception {
            final IdentityProvider<?> idp = buildSamlIdpWithAliasProperties(zone.getId(), null, null);
            final IdentityProvider<?> createdProvider = createIdp(zone, idp);
            assertThat(createdProvider.getAliasZid()).isBlank();
            createdProvider.setAliasId(UUID.randomUUID().toString());
            shouldRejectUpdate(zone, createdProvider, HttpStatus.UNPROCESSABLE_ENTITY);
        }

        @Test
        void shouldReject_AliasNotSupportedForIdpType_UaaToCustomZone() throws Exception {
            shouldReject_AliasNotSupportedForIdpType(IdentityZone.getUaa(), customZone);
        }

        @Test
        void shouldReject_AliasNotSupportedForIdpType_CustomZone() throws Exception {
            shouldReject_AliasNotSupportedForIdpType(customZone, IdentityZone.getUaa());
        }

        private void shouldReject_AliasNotSupportedForIdpType(final IdentityZone zone1, final IdentityZone zone2) throws Exception {
            final IdentityProvider<?> uaaIdp = buildUaaIdpWithAliasProperties(zone1.getId(), null, null);
            final IdentityProvider<?> createdProvider = createIdp(zone1, uaaIdp);
            assertThat(createdProvider.getAliasZid()).isBlank();

            // try to create an alias for the IdP -> should fail because of the IdP's type
            createdProvider.setAliasZid(zone2.getId());
            shouldRejectUpdate(zone1, createdProvider, HttpStatus.UNPROCESSABLE_ENTITY);
        }

        @Test
        void shouldReject_IdpWithOriginKeyAlreadyPresentInOtherZone_UaaToCustomZone() throws Exception {
            shouldReject_IdpWithOriginKeyAlreadyPresentInOtherZone(IdentityZone.getUaa(), customZone);
        }

        @Test
        void shouldReject_IdpWithOriginKeyAlreadyPresentInOtherZone_CustomToUaaZone() throws Exception {
            shouldReject_IdpWithOriginKeyAlreadyPresentInOtherZone(customZone, IdentityZone.getUaa());
        }

        private void shouldReject_IdpWithOriginKeyAlreadyPresentInOtherZone(final IdentityZone zone1, final IdentityZone zone2) throws Exception {
            // create IdP with origin key in zone 2
            final IdentityProvider<?> existingIdpInZone2 = buildSamlIdpWithAliasProperties(zone2.getId(), null, null);
            createIdp(zone2, existingIdpInZone2);

            // create IdP with same origin key in zone 1
            final IdentityProvider<?> idp = buildIdpWithAliasProperties(
                    zone1.getId(),
                    null,
                    null,
                    existingIdpInZone2.getOriginKey(), // same origin key
                    SAML
            );
            final IdentityProvider<?> providerInZone1 = createIdp(zone1, idp);

            // update the alias ZID to zone 2, where an IdP with this origin already exists -> should fail
            providerInZone1.setAliasZid(zone2.getId());
            shouldRejectUpdate(zone1, providerInZone1, HttpStatus.CONFLICT);
        }

        @Test
        void shouldReject_IdpInCustomZone_AliasToOtherCustomZone() throws Exception {
            final IdentityProvider<?> idpInCustomZone = createIdp(
                    customZone,
                    buildSamlIdpWithAliasProperties(customZone.getId(), null, null)
            );

            // try to create an alias in another custom zone -> should fail
            idpInCustomZone.setAliasZid("not-uaa");
            shouldRejectUpdate(customZone, idpInCustomZone, HttpStatus.UNPROCESSABLE_ENTITY);
        }

        @Test
        void shouldReject_AliasZidSetToSameZone_UaaZone() throws Exception {
            shouldReject_AliasZidSetToSameZone(IdentityZone.getUaa());
        }

        @Test
        void shouldReject_AliasZidSetToSameZone_CustomZone() throws Exception {
            shouldReject_AliasZidSetToSameZone(customZone);
        }

        private void shouldReject_AliasZidSetToSameZone(final IdentityZone zone) throws Exception {
            final IdentityProvider<?> idp = createIdp(
                    zone,
                    buildSamlIdpWithAliasProperties(zone.getId(), null, null)
            );
            idp.setAliasZid(zone.getId());
            shouldRejectUpdate(zone, idp, HttpStatus.UNPROCESSABLE_ENTITY);
        }

        private IdentityProvider<?> updateIdp(final IdentityZone zone, final IdentityProvider<?> updatePayload) throws Exception {
            updatePayload.setIdentityZoneId(zone.getId());
            final MvcResult result = updateIdpAndReturnResult(zone, updatePayload);
            assertThat(result.getResponse().getStatus()).isEqualTo(HttpStatus.OK.value());

            final IdentityProvider<?> originalIdpAfterUpdate = JsonUtils.readValue(
                    result.getResponse().getContentAsString(),
                    IdentityProvider.class
            );
            assertThat(originalIdpAfterUpdate).isNotNull();
            assertThat(originalIdpAfterUpdate.getIdentityZoneId()).isNotBlank();
            assertThat(originalIdpAfterUpdate.getIdentityZoneId()).isEqualTo(zone.getId());
            return originalIdpAfterUpdate;
        }

        private MvcResult updateIdpAndReturnResult(final IdentityZone zone, final IdentityProvider<?> updatePayload) throws Exception {
            final String id = updatePayload.getId();
            assertThat(id).isNotNull().isNotBlank();

            final MockHttpServletRequestBuilder updateRequestBuilder = put("/identity-providers/" + id)
                    .header("Authorization", "Bearer " + getAccessTokenForZone(zone.getId()))
                    .header(IdentityZoneSwitchingFilter.HEADER, zone.getId())
                    .contentType(APPLICATION_JSON)
                    .content(JsonUtils.writeValueAsString(updatePayload));
            return mockMvc.perform(updateRequestBuilder).andReturn();
        }

        private void shouldRejectUpdate(final IdentityZone zone, final IdentityProvider<?> idp, final HttpStatus expectedErrorStatus) throws Exception {
            assertThat(idp.getId()).isNotBlank();
            assertThat(expectedErrorStatus.isError()).isTrue();

            // read existing IdP before update
            final String id = idp.getId();
            final Optional<IdentityProvider<?>> idpBeforeUpdateOpt = readIdpFromZoneIfExists(zone.getId(), id);
            assertThat(idpBeforeUpdateOpt).isPresent();
            final IdentityProvider<?> idpBeforeUpdate = idpBeforeUpdateOpt.get();

            // if alias properties set: read alias IdP before update
            final IdentityProvider<?> aliasIdpBeforeUpdate;
            if (hasText(idpBeforeUpdate.getAliasId()) && hasText(idpBeforeUpdate.getAliasZid())) {
                final Optional<IdentityProvider<?>> aliasIdpBeforeUpdateOpt = readIdpFromZoneIfExists(
                        idpBeforeUpdate.getAliasZid(),
                        idpBeforeUpdate.getAliasId()
                );
                assertThat(aliasIdpBeforeUpdateOpt).isPresent();
                aliasIdpBeforeUpdate = aliasIdpBeforeUpdateOpt.get();
            } else {
                aliasIdpBeforeUpdate = null;
            }

            // perform the update -> should fail
            final MvcResult result = updateIdpAndReturnResult(zone, idp);
            assertThat(result.getResponse().getStatus()).isEqualTo(expectedErrorStatus.value());

            // read again: original IdP should remain unchanged
            final Optional<IdentityProvider<?>> idpAfterFailedUpdateOpt = readIdpFromZoneIfExists(
                    zone.getId(),
                    idp.getId()
            );
            assertThat(idpAfterFailedUpdateOpt).isPresent().contains(idpBeforeUpdate);

            // if an alias IdP was present before update, check if it also remains unchanged
            if (aliasIdpBeforeUpdate != null) {
                final Optional<IdentityProvider<?>> aliasIdpAfterFailedUpdateOpt = readIdpFromZoneIfExists(
                        idpBeforeUpdate.getAliasZid(),
                        idpBeforeUpdate.getAliasId()
                );
                assertThat(aliasIdpAfterFailedUpdateOpt).isPresent().contains(aliasIdpBeforeUpdate);
            }
        }
    }

    private void deleteIdpViaDb(final String originKey, final String zoneId) {
        final JdbcIdentityProviderProvisioning identityProviderProvisioning = webApplicationContext
                .getBean(JdbcIdentityProviderProvisioning.class);
        final int rowsDeleted = identityProviderProvisioning.deleteByOrigin(originKey, zoneId);
        assertThat(rowsDeleted).isEqualTo(1);
    }

    @Nested
    class Delete {
        @Test
        void shouldAlsoDeleteAliasIdp_UaaToCustomZone() throws Exception {
            shouldAlsoDeleteAliasIdp(IdentityZone.getUaa(), customZone);
        }

        @Test
        void shouldAlsoDeleteAliasIdp_CustomToUaaZone() throws Exception {
            shouldAlsoDeleteAliasIdp(customZone, IdentityZone.getUaa());
        }

        private void shouldAlsoDeleteAliasIdp(final IdentityZone zone1, final IdentityZone zone2) throws Exception {
            final IdentityProvider<?> idpInZone1 = createIdpWithAlias(zone1, zone2);
            final String id = idpInZone1.getId();
            assertThat(id).isNotBlank();
            final String aliasId = idpInZone1.getAliasId();
            assertThat(aliasId).isNotBlank();
            final String aliasZid = idpInZone1.getAliasZid();
            assertThat(aliasZid).isNotBlank().isEqualTo(zone2.getId());

            // check if alias IdP is available in zone 2
            final Optional<IdentityProvider<?>> aliasIdp = readIdpFromZoneIfExists(zone2.getId(), aliasId);
            assertThat(aliasIdp).isPresent();
            assertThat(aliasIdp.get().getAliasId()).isNotBlank().isEqualTo(id);
            assertThat(aliasIdp.get().getAliasZid()).isNotBlank().isEqualTo(idpInZone1.getIdentityZoneId());

            // delete IdP in zone 1
            final MvcResult deleteResult = deleteIdpAndReturnResult(zone1, id);
            assertThat(deleteResult.getResponse().getStatus()).isEqualTo(HttpStatus.OK.value());

            // check if IdP is no longer available in zone 2
            assertIdpDoesNotExist(zone2, aliasId);
        }

        @Test
        void shouldIgnoreDanglingReferenceToAliasIdp_UaaToCustomZone() throws Exception {
            shouldIgnoreDanglingReferenceToAliasIdp(IdentityZone.getUaa(), customZone);
        }

        @Test
        void shouldIgnoreDanglingReferenceToAliasIdp_CustomToUaaZone() throws Exception {
            shouldIgnoreDanglingReferenceToAliasIdp(customZone, IdentityZone.getUaa());
        }

        private void shouldIgnoreDanglingReferenceToAliasIdp(final IdentityZone zone1, final IdentityZone zone2) throws Exception {
            final IdentityProvider<?> originalIdp = createIdpWithAlias(zone1, zone2);

            // create a dangling reference by deleting the alias IdP directly in the DB
            deleteIdpViaDb(originalIdp.getOriginKey(), zone2.getId());

            // delete the original IdP -> dangling reference should be ignored
            final MvcResult deleteResult = deleteIdpAndReturnResult(zone1, originalIdp.getId());
            assertThat(deleteResult.getResponse().getStatus()).isEqualTo(HttpStatus.OK.value());

            // original IdP should no longer exist
            assertIdpDoesNotExist(zone1, originalIdp.getId());
        }

        private MvcResult deleteIdpAndReturnResult(final IdentityZone zone, final String id) throws Exception {
            final String accessTokenForZone1 = getAccessTokenForZone(zone.getId());
            final MockHttpServletRequestBuilder deleteRequestBuilder = delete("/identity-providers/" + id)
                    .header("Authorization", "Bearer " + accessTokenForZone1)
                    .header(IdentityZoneSwitchingFilter.HEADER, zone.getId());
            return mockMvc.perform(deleteRequestBuilder).andReturn();
        }

        private void assertIdpDoesNotExist(final IdentityZone zone, final String id) throws Exception {
            final Optional<IdentityProvider<?>> idp = readIdpFromZoneIfExists(zone.getId(), id);
            assertThat(idp).isNotPresent();
        }
    }

    private void assertIdpReferencesOtherIdp(final IdentityProvider<?> idp, final IdentityProvider<?> referencedIdp) {
        assertThat(idp).isNotNull();
        assertThat(referencedIdp).isNotNull();
        assertThat(referencedIdp.getId()).isNotBlank().isEqualTo(idp.getAliasId());
        assertThat(referencedIdp.getIdentityZoneId()).isNotBlank().isEqualTo(idp.getAliasZid());
    }

    private void assertOtherPropertiesAreEqual(final IdentityProvider<?> idp, final IdentityProvider<?> aliasIdp) {
        // apart from the zone ID, the configs should be identical
        final SamlIdentityProviderDefinition originalIdpConfig = (SamlIdentityProviderDefinition) idp.getConfig();
        originalIdpConfig.setZoneId(null);
        final SamlIdentityProviderDefinition aliasIdpConfig = (SamlIdentityProviderDefinition) aliasIdp.getConfig();
        aliasIdpConfig.setZoneId(null);
        assertThat(aliasIdpConfig).isEqualTo(originalIdpConfig);

        // check if remaining properties are equal
        assertThat(aliasIdp.getOriginKey()).isEqualTo(idp.getOriginKey());
        assertThat(aliasIdp.getName()).isEqualTo(idp.getName());
        assertThat(aliasIdp.getType()).isEqualTo(idp.getType());
    }

    private IdentityProvider<?> createIdpWithAlias(final IdentityZone zone1, final IdentityZone zone2) throws Exception {
        final IdentityProvider<?> provider = buildSamlIdpWithAliasProperties(zone1.getId(), null, zone2.getId());
        final IdentityProvider<?> createdOriginalIdp = createIdp(zone1, provider);
        assertThat(createdOriginalIdp.getAliasId()).isNotBlank();
        assertThat(createdOriginalIdp.getAliasZid()).isNotBlank();
        return createdOriginalIdp;
    }

    private IdentityProvider<?> createIdp(final IdentityZone zone, final IdentityProvider<?> idp) throws Exception {
        final MvcResult createResult = createIdpAndReturnResult(zone, idp);
        assertThat(createResult.getResponse().getStatus()).isEqualTo(HttpStatus.CREATED.value());
        return JsonUtils.readValue(createResult.getResponse().getContentAsString(), IdentityProvider.class);
    }

    private MvcResult createIdpAndReturnResult(final IdentityZone zone, final IdentityProvider<?> idp) throws Exception {
        final MockHttpServletRequestBuilder createRequestBuilder = post("/identity-providers")
                .param("rawConfig", "true")
                .header("Authorization", "Bearer " + getAccessTokenForZone(zone.getId()))
                .header(IdentityZoneSwitchingFilter.SUBDOMAIN_HEADER, zone.getSubdomain())
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(idp));
        return mockMvc.perform(createRequestBuilder).andReturn();
    }

    private String getAccessTokenForZone(final String zoneId) throws Exception {
        final String cacheLookupResult = accessTokenCache.get(zoneId);
        if (cacheLookupResult != null) {
            return cacheLookupResult;
        }

        final List<String> scopesForZone = getScopesForZone(zoneId, "admin");

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
        assertThat(claims).containsKey("scope");
        assertThat(claims.get("scope")).isInstanceOf(List.class);
        final List<String> resultingScopes = (List<String>) claims.get("scope");
        assertThat(resultingScopes).hasSameElementsAs(scopesForZone);

        // cache the access token
        accessTokenCache.put(zoneId, accessToken);

        return accessToken;
    }

    private Optional<IdentityProvider<?>> readIdpFromZoneIfExists(final String zoneId, final String id) throws Exception {
        final MockHttpServletRequestBuilder getRequestBuilder = get("/identity-providers/" + id)
                .param("rawConfig", "true")
                .header(IdentityZoneSwitchingFilter.HEADER, zoneId)
                .header("Authorization", "Bearer " + getAccessTokenForZone(zoneId));
        final MvcResult getResult = mockMvc.perform(getRequestBuilder).andReturn();
        final int responseStatus = getResult.getResponse().getStatus();
        assertThat(responseStatus).isIn(404, 200);

        switch (responseStatus) {
            case 404:
                return Optional.empty();
            case 200:
                final IdentityProvider<?> responseBody = JsonUtils.readValue(
                        getResult.getResponse().getContentAsString(),
                        IdentityProvider.class
                );
                return Optional.ofNullable(responseBody);
            default:
                // should not happen
                return Optional.empty();
        }
    }

    private List<IdentityProvider<?>> readAllIdpsInZone(final IdentityZone zone) throws Exception {
        final MockHttpServletRequestBuilder getRequestBuilder = get("/identity-providers")
                .param("rawConfig", "true")
                .header(IdentityZoneSwitchingFilter.SUBDOMAIN_HEADER, zone.getSubdomain())
                .header("Authorization", "Bearer " + getAccessTokenForZone(zone.getId()));
        final MvcResult getResult = mockMvc.perform(getRequestBuilder).andExpect(status().isOk()).andReturn();
        return JsonUtils.readValue(getResult.getResponse().getContentAsString(), new TypeReference<>() {
        });
    }

    private static List<String> getScopesForZone(final String zoneId, final String... scopes) {
        return Stream.of(scopes).map(scope -> String.format("zones.%s.%s", zoneId, scope)).collect(toList());
    }

    private static IdentityProvider<?> buildSamlIdpWithAliasProperties(
            final String idzId,
            final String aliasId,
            final String aliasZid
    ) {
        final String originKey = RANDOM_STRING_GENERATOR.generate();
        return buildIdpWithAliasProperties(idzId, aliasId, aliasZid, originKey, SAML);
    }

    private IdentityProvider<?> buildUaaIdpWithAliasProperties(
            final String idzId,
            final String aliasId,
            final String aliasZid
    ) {
        final String originKey = RANDOM_STRING_GENERATOR.generate();
        return buildIdpWithAliasProperties(idzId, aliasId, aliasZid, originKey, UAA);
    }

    private static IdentityProvider<?> buildIdpWithAliasProperties(
            final String idzId,
            final String aliasId,
            final String aliasZid,
            final String originKey,
            final String type
    ) {
        final AbstractIdentityProviderDefinition definition = buildIdpDefinition(originKey, type);

        final IdentityProvider<AbstractIdentityProviderDefinition> provider = new IdentityProvider<>();
        provider.setIdentityZoneId(idzId);
        provider.setAliasId(aliasId);
        provider.setAliasZid(aliasZid);
        provider.setName(originKey);
        provider.setOriginKey(originKey);
        provider.setType(type);
        provider.setConfig(definition);
        provider.setActive(true);
        return provider;
    }

    private static AbstractIdentityProviderDefinition buildIdpDefinition(final String originKey, final String type) {
        switch (type) {
            case SAML:
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

                return samlDefinition;
            case UAA:
                final PasswordPolicy passwordPolicy = new PasswordPolicy();
                passwordPolicy.setExpirePasswordInMonths(1);
                passwordPolicy.setMaxLength(100);
                passwordPolicy.setMinLength(10);
                passwordPolicy.setRequireDigit(1);
                passwordPolicy.setRequireUpperCaseCharacter(1);
                passwordPolicy.setRequireLowerCaseCharacter(1);
                passwordPolicy.setRequireSpecialCharacter(1);
                passwordPolicy.setPasswordNewerThan(new Date(System.currentTimeMillis()));
                return new UaaIdentityProviderDefinition(passwordPolicy, null);
            default:
                throw new IllegalArgumentException("IdP type not supported.");
        }
    }
}
