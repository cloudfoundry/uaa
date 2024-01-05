package org.cloudfoundry.identity.uaa.mock.providers;

import static java.util.Collections.singletonList;
import static java.util.Collections.singletonMap;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toSet;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
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

import org.apache.commons.lang.RandomStringUtils;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderStatus;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
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
import org.springframework.web.context.WebApplicationContext;

import com.fasterxml.jackson.core.type.TypeReference;

/**
 * Tests regarding the handling of "aliasId" and "aliasZid" properties of identity providers.
 */
@DefaultTestContext
class IdentityProviderEndpointsAliasMockMvcTests {

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
        void shouldAccept_MirrorIdp_UaaToCustomZone() throws Exception {
            shouldAccept_MirrorIdp(IdentityZone.getUaa(), customZone);
        }

        @Test
        void shouldAccept_MirrorIdp_CustomToUaaZone() throws Exception {
            shouldAccept_MirrorIdp(customZone, IdentityZone.getUaa());
        }

        private void shouldAccept_MirrorIdp(final IdentityZone zone1, final IdentityZone zone2) throws Exception {
            // build IdP in zone1 with aliasZid set to zone2
            final IdentityProvider<?> provider = buildIdpWithAliasProperties(zone1.getId(), null, zone2.getId());

            // create IdP in zone1
            final IdentityProvider<?> originalIdp = createIdp(zone1, provider);
            assertThat(originalIdp).isNotNull();
            assertThat(originalIdp.getAliasId()).isNotBlank();
            assertThat(originalIdp.getAliasZid()).isNotBlank().isEqualTo(zone2.getId());

            // read mirrored IdP from zone2
            final String id = originalIdp.getAliasId();
            final Optional<IdentityProvider<?>> mirroredIdp = readIdpFromZoneIfExists(zone2.getId(), id);
            assertThat(mirroredIdp).isPresent();
            assertIdpReferencesOtherIdp(mirroredIdp.get(), originalIdp);
            assertOtherPropertiesAreEqual(originalIdp, mirroredIdp.get());

            // check if aliasId in first IdP is equal to the ID of the mirrored one
            assertThat(mirroredIdp.get().getId()).isEqualTo(originalIdp.getAliasId());
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
            final IdentityProvider<?> idp = buildIdpWithAliasProperties(zone.getId(), null, zone.getId());
            shouldRejectCreation(zone, idp, HttpStatus.UNPROCESSABLE_ENTITY);
        }

        @Test
        void shouldReject_NeitherIdzNorAliasZidIsUaa() throws Exception {
            final IdentityZone otherCustomZone = MockMvcUtils.createZoneUsingWebRequest(mockMvc, identityToken);
            final IdentityProvider<?> idp = buildIdpWithAliasProperties(customZone.getId(), null, otherCustomZone.getId());
            shouldRejectCreation(customZone, idp, HttpStatus.UNPROCESSABLE_ENTITY);
        }

        @Test
        void shouldReject_AliasIdIsSet() throws Exception {
            final String aliasId = UUID.randomUUID().toString();
            final IdentityProvider<?> idp = buildIdpWithAliasProperties(customZone.getId(), aliasId, IdentityZone.getUaaZoneId());
            shouldRejectCreation(customZone, idp, HttpStatus.UNPROCESSABLE_ENTITY);
        }

        @Test
        void shouldReject_IdzReferencedInAliasZidDoesNotExist() throws Exception {
            final IdentityProvider<?> provider = buildIdpWithAliasProperties(
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
            final String originKey = RandomStringUtils.randomAlphabetic(10);

            // create IdP with origin key in custom zone
            final IdentityProvider<?> createdIdp1 = createIdp(
                    zone1,
                    buildIdpWithAliasProperties(zone1.getId(), null, null, originKey)
            );
            assertThat(createdIdp1).isNotNull();

            // then, create an IdP in the "uaa" zone with the same origin key that should be mirrored to the custom zone
            shouldRejectCreation(
                    zone2,
                    buildIdpWithAliasProperties(zone2.getId(), null, zone1.getId(), originKey),
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
        void shouldAccept_ShouldCreateMirroredIdp_UaaToCustomZone() throws Exception {
            shouldAccept_ShouldCreateMirroredIdp(IdentityZone.getUaa(), customZone);
        }

        @Test
        void shouldAccept_ShouldCreateMirroredIdp_CustomToUaaZone() throws Exception {
            shouldAccept_ShouldCreateMirroredIdp(customZone, IdentityZone.getUaa());
        }

        private void shouldAccept_ShouldCreateMirroredIdp(final IdentityZone zone1, final IdentityZone zone2) throws Exception {
            // create regular idp without alias properties in UAA zone
            final IdentityProvider<?> existingIdpWithoutAlias = createIdp(
                    zone1,
                    buildIdpWithAliasProperties(zone1.getId(), null, null)
            );
            assertThat(existingIdpWithoutAlias).isNotNull();
            assertThat(existingIdpWithoutAlias.getId()).isNotBlank();

            // perform update: set Alias ZID
            existingIdpWithoutAlias.setAliasZid(zone2.getId());
            final IdentityProvider<?> idpAfterUpdate = updateIdp(zone1, existingIdpWithoutAlias);
            assertThat(idpAfterUpdate.getAliasId()).isNotBlank();
            assertThat(idpAfterUpdate.getAliasZid()).isNotBlank();
            assertThat(zone2.getId()).isEqualTo(idpAfterUpdate.getAliasZid());

            // read mirrored IdP through alias id in original IdP
            final String id = idpAfterUpdate.getAliasId();
            final Optional<IdentityProvider<?>> idp = readIdpFromZoneIfExists(zone2.getId(), id);
            assertThat(idp).isPresent();
            final IdentityProvider<?> mirroredIdp = idp.get();
            assertIdpReferencesOtherIdp(mirroredIdp, idpAfterUpdate);
            assertOtherPropertiesAreEqual(idpAfterUpdate, mirroredIdp);
        }

        @Test
        void shouldAccept_OtherPropertiesOfAlreadyMirroredIdpAreChanged_UaaToCustomZone() throws Exception {
            shouldAccept_OtherPropertiesOfAlreadyMirroredIdpAreChanged(IdentityZone.getUaa(), customZone);
        }

        @Test
        void shouldAccept_OtherPropertiesOfAlreadyMirroredIdpAreChanged_CustomToUaaZone() throws Exception {
            shouldAccept_OtherPropertiesOfAlreadyMirroredIdpAreChanged(customZone, IdentityZone.getUaa());
        }

        private void shouldAccept_OtherPropertiesOfAlreadyMirroredIdpAreChanged(final IdentityZone zone1, final IdentityZone zone2) throws Exception {
            // create a mirrored IdP
            final IdentityProvider<?> originalIdp = createMirroredIdp(zone1, zone2);

            // update other property
            final String newName = "new name";
            originalIdp.setName(newName);
            final IdentityProvider<?> updatedOriginalIdp = updateIdp(zone1, originalIdp);
            assertThat(updatedOriginalIdp).isNotNull();
            assertThat(updatedOriginalIdp.getAliasId()).isNotBlank();
            assertThat(updatedOriginalIdp.getAliasZid()).isNotBlank();
            assertThat(updatedOriginalIdp.getAliasZid()).isEqualTo(zone2.getId());
            assertThat(updatedOriginalIdp.getName()).isNotBlank().isEqualTo(newName);

            // check if the change is propagated to the mirrored IdP
            final String id = updatedOriginalIdp.getAliasId();
            final Optional<IdentityProvider<?>> mirroredIdp = readIdpFromZoneIfExists(zone2.getId(), id);
            assertThat(mirroredIdp).isPresent();
            assertIdpReferencesOtherIdp(mirroredIdp.get(), updatedOriginalIdp);
            assertThat(mirroredIdp.get().getName()).isNotBlank().isEqualTo(newName);
        }

        @Test
        void shouldAccept_ReferencedIdpNotExisting_ShouldCreateNewMirroredIdp_UaaToCustomZone() throws Exception {
            shouldAccept_ReferencedIdpNotExisting_ShouldCreateNewMirroredIdp(IdentityZone.getUaa(), customZone);
        }

        @Test
        void shouldAccept_ReferencedIdpNotExisting_ShouldCreateNewMirroredIdp_CustomToUaaZone() throws Exception {
            shouldAccept_ReferencedIdpNotExisting_ShouldCreateNewMirroredIdp(customZone, IdentityZone.getUaa());
        }

        private void shouldAccept_ReferencedIdpNotExisting_ShouldCreateNewMirroredIdp(final IdentityZone zone1, final IdentityZone zone2) throws Exception {
            final IdentityProvider<?> idp = createMirroredIdp(zone1, zone2);

            // delete the mirrored IdP directly in the DB -> after that, there is a dangling reference
            final JdbcIdentityProviderProvisioning identityProviderProvisioning = webApplicationContext.getBean(JdbcIdentityProviderProvisioning.class);
            final int rowsDeleted = identityProviderProvisioning.deleteByOrigin(idp.getOriginKey(), zone2.getId());
            assertThat(rowsDeleted).isEqualTo(1);

            // update some other property on the original IdP
            idp.setName("some-new-name");
            final IdentityProvider<?> updatedIdp = updateIdp(zone1, idp);
            assertThat(updatedIdp.getAliasId()).isNotBlank().isNotEqualTo(idp.getAliasId());
            assertThat(updatedIdp.getAliasZid()).isNotBlank().isEqualTo(idp.getAliasZid());

            // check if the new mirrored IdP is present and has the correct properties
            final String id = updatedIdp.getAliasId();
            final Optional<IdentityProvider<?>> mirroredIdp = readIdpFromZoneIfExists(zone2.getId(), id);
            assertThat(mirroredIdp).isPresent();
            assertIdpReferencesOtherIdp(updatedIdp, mirroredIdp.get());
            assertOtherPropertiesAreEqual(updatedIdp, mirroredIdp.get());
        }

        @ParameterizedTest
        @MethodSource("shouldReject_ChangingAliasPropertiesOfAlreadyMirroredIdp")
        void shouldReject_ChangingAliasPropertiesOfAlreadyMirroredIdp_UaaToCustomZone(final String newAliasId, final String newAliasZid) throws Exception {
            shouldReject_ChangingAliasPropertiesOfAlreadyMirroredIdp(newAliasId, newAliasZid, IdentityZone.getUaa(), customZone);
        }

        @ParameterizedTest
        @MethodSource("shouldReject_ChangingAliasPropertiesOfAlreadyMirroredIdp")
        void shouldReject_ChangingAliasPropertiesOfAlreadyMirroredIdp_CustomToUaaZone(final String newAliasId, final String newAliasZid) throws Exception {
            shouldReject_ChangingAliasPropertiesOfAlreadyMirroredIdp(newAliasId, newAliasZid, customZone, IdentityZone.getUaa());
        }

        private void shouldReject_ChangingAliasPropertiesOfAlreadyMirroredIdp(
                final String newAliasId,
                final String newAliasZid,
                final IdentityZone zone1,
                final IdentityZone zone2
        ) throws Exception {
            final IdentityProvider<?> originalIdp = createMirroredIdp(zone1, zone2);
            originalIdp.setAliasId(newAliasId);
            originalIdp.setAliasZid(newAliasZid);
            shouldRejectUpdate(zone1, originalIdp, HttpStatus.UNPROCESSABLE_ENTITY);
        }

        private static Stream<Arguments> shouldReject_ChangingAliasPropertiesOfAlreadyMirroredIdp() {
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
            final IdentityProvider<?> idp = buildIdpWithAliasProperties(zone.getId(), null, null);
            final IdentityProvider<?> createdProvider = createIdp(zone, idp);
            assertThat(createdProvider.getAliasZid()).isBlank();
            createdProvider.setAliasId(UUID.randomUUID().toString());
            shouldRejectUpdate(zone, createdProvider, HttpStatus.UNPROCESSABLE_ENTITY);
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
            final String originKey = RandomStringUtils.randomAlphabetic(10);

            // create IdP with origin key in zone 2
            final IdentityProvider<?> existingIdpInZone2 = buildIdpWithAliasProperties(
                    zone2.getId(),
                    null,
                    null,
                    originKey
            );
            createIdp(zone2, existingIdpInZone2);

            // create IdP with same origin key in zone 1
            final IdentityProvider<?> idp = buildIdpWithAliasProperties(
                    zone1.getId(),
                    null,
                    null,
                    originKey // same origin key
            );
            final IdentityProvider<?> providerInZone1 = createIdp(zone1, idp);

            // update the alias ZID to zone 2, where an IdP with this origin already exists -> should fail
            providerInZone1.setAliasZid(zone2.getId());
            shouldRejectUpdate(zone1, providerInZone1, HttpStatus.INTERNAL_SERVER_ERROR);
        }

        @Test
        void shouldReject_IdpInCustomZoneMirroredToOtherCustomZone() throws Exception {
            final IdentityProvider<?> idpInCustomZone = createIdp(
                    customZone,
                    buildIdpWithAliasProperties(customZone.getId(), null, null)
            );

            // try to mirror it to another custom zone
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
                    buildIdpWithAliasProperties(zone.getId(), null, null)
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

            // if alias properties set: read mirrored IdP before update
            final IdentityProvider<?> mirroredIdpBeforeUpdate;
            if (hasText(idpBeforeUpdate.getAliasId()) && hasText(idpBeforeUpdate.getAliasZid())) {
                final Optional<IdentityProvider<?>> mirroredIdpBeforeUpdateOpt = readIdpFromZoneIfExists(
                        idpBeforeUpdate.getAliasZid(),
                        idpBeforeUpdate.getAliasId()
                );
                assertThat(mirroredIdpBeforeUpdateOpt).isPresent();
                mirroredIdpBeforeUpdate = mirroredIdpBeforeUpdateOpt.get();
            } else {
                mirroredIdpBeforeUpdate = null;
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

            // if a mirrored IdP was present before update, check if it also remains unchanged
            if (mirroredIdpBeforeUpdate != null) {
                final Optional<IdentityProvider<?>> mirroredIdpAfterFailedUpdateOpt = readIdpFromZoneIfExists(
                        idpBeforeUpdate.getAliasZid(),
                        idpBeforeUpdate.getAliasId()
                );
                assertThat(mirroredIdpAfterFailedUpdateOpt).isPresent().contains(mirroredIdpBeforeUpdate);
            }
        }
    }

    @Nested
    class Delete {
        @Test
        void shouldDeleteMirroredIdp_UaaToCustomZone() throws Exception {
            shouldDeleteMirroredIdp(IdentityZone.getUaa(), customZone);
        }

        @Test
        void shouldDeleteMirroredIdp_CustomToUaaZone() throws Exception {
            shouldDeleteMirroredIdp(customZone, IdentityZone.getUaa());
        }

        private void shouldDeleteMirroredIdp(final IdentityZone zone1, final IdentityZone zone2) throws Exception {
            final IdentityProvider<?> idpInZone1 = createMirroredIdp(zone1, zone2);
            final String id = idpInZone1.getId();
            assertThat(id).isNotBlank();
            final String aliasId = idpInZone1.getAliasId();
            assertThat(aliasId).isNotBlank();
            final String aliasZid = idpInZone1.getAliasZid();
            assertThat(aliasZid).isNotBlank().isEqualTo(zone2.getId());

            // check if mirrored IdP is available in zone 2
            final Optional<IdentityProvider<?>> mirroredIdp = readIdpFromZoneIfExists(zone2.getId(), aliasId);
            assertThat(mirroredIdp).isPresent();
            assertThat(mirroredIdp.get().getAliasId()).isNotBlank().isEqualTo(id);
            assertThat(mirroredIdp.get().getAliasZid()).isNotBlank().isEqualTo(idpInZone1.getIdentityZoneId());

            // delete IdP in zone 1
            final String accessTokenForZone1 = getAccessTokenForZone(zone1.getId());
            final MockHttpServletRequestBuilder deleteRequestBuilder = delete("/identity-providers/" + id)
                    .header("Authorization", "Bearer " + accessTokenForZone1)
                    .header(IdentityZoneSwitchingFilter.HEADER, zone1.getId());
            final MvcResult response = mockMvc.perform(deleteRequestBuilder).andReturn();

            assertThat(response.getResponse().getStatus()).isEqualTo(200);

            // check if IdP is no longer available in zone 2
            final Optional<IdentityProvider<?>> mirroredIdpAfterDeletionOfOriginalIdp = readIdpFromZoneIfExists(zone2.getId(), aliasId);
            assertThat(mirroredIdpAfterDeletionOfOriginalIdp).isNotPresent();
        }
    }

    @Nested
    class UpdateStatus {
        @Test
        void shouldAccept_MirroredIdpShouldAlsoBeUpdated_UaaToCustomZone() throws Exception {
            shouldAccept_MirroredIdpShouldAlsoBeUpdated(IdentityZone.getUaa(), customZone);
        }

        @Test
        void shouldAccept_MirroredIdpShouldAlsoBeUpdated_CustomToUaaZone() throws Exception {
            shouldAccept_MirroredIdpShouldAlsoBeUpdated(customZone, IdentityZone.getUaa());
        }

        private void shouldAccept_MirroredIdpShouldAlsoBeUpdated(final IdentityZone zone1, final IdentityZone zone2) throws Exception {
            // create an IdP of type UAA
            final IdentityProvider<UaaIdentityProviderDefinition> idp = new IdentityProvider<>();
            idp.setType(OriginKeys.UAA);
            idp.setName("some-name");
            idp.setOriginKey(RandomStringUtils.randomAlphabetic(8));
            final PasswordPolicy passwordPolicy = new PasswordPolicy();
            passwordPolicy.setExpirePasswordInMonths(1);
            passwordPolicy.setMaxLength(100);
            passwordPolicy.setMinLength(10);
            passwordPolicy.setRequireDigit(1);
            passwordPolicy.setRequireUpperCaseCharacter(1);
            passwordPolicy.setRequireLowerCaseCharacter(1);
            passwordPolicy.setRequireSpecialCharacter(1);
            passwordPolicy.setPasswordNewerThan(new Date(System.currentTimeMillis()));
            idp.setConfig(new UaaIdentityProviderDefinition(passwordPolicy, null));
            idp.setAliasZid(zone2.getId());
            final String accessTokenForZone1 = getAccessTokenForZone(zone1.getId());
            final IdentityProvider<?> createdIdp = createIdp(zone1, idp);

            final Date timestampBeforeUpdate = getPasswordNewerThanTimestamp(createdIdp);
            assertThat(timestampBeforeUpdate).isNotNull();

            final IdentityProviderStatus identityProviderStatus = new IdentityProviderStatus();
            identityProviderStatus.setRequirePasswordChange(true);
            final MockHttpServletRequestBuilder updateRequestBuilder = patch("/identity-providers/" + createdIdp.getId() + "/status")
                    .header("Authorization", "Bearer " + accessTokenForZone1)
                    .header(IdentityZoneSwitchingFilter.HEADER, zone1.getId())
                    .contentType(APPLICATION_JSON)
                    .content(JsonUtils.writeValueAsString(identityProviderStatus));
            mockMvc.perform(updateRequestBuilder).andExpect(status().isOk()).andReturn();

            // check if timestamp is updated in zone 1
            final String id1 = createdIdp.getId();
            final Optional<IdentityProvider<?>> idpInZone1 = readIdpFromZoneIfExists(zone1.getId(), id1);
            assertThat(idpInZone1).isPresent();
            final Date timestampAfterUpdate = getPasswordNewerThanTimestamp(idpInZone1.get());
            assertThat(timestampAfterUpdate).isAfter(timestampBeforeUpdate);

            // check if timestamp is updated in zone 2
            final String id = createdIdp.getAliasId();
            final Optional<IdentityProvider<?>> idpInZone2 = readIdpFromZoneIfExists(zone2.getId(), id);
            assertThat(idpInZone2).isPresent();
            final Date timestampAfterUpdateMirroredIdp = getPasswordNewerThanTimestamp(idpInZone2.get());
            assertThat(timestampAfterUpdateMirroredIdp).isEqualTo(timestampAfterUpdate);
        }

        private Date getPasswordNewerThanTimestamp(final IdentityProvider<?> idp) {
            return ((UaaIdentityProviderDefinition) idp.getConfig()).getPasswordPolicy().getPasswordNewerThan();
        }
    }

    private void assertIdpReferencesOtherIdp(final IdentityProvider<?> idp, final IdentityProvider<?> referencedIdp) {
        assertThat(idp).isNotNull();
        assertThat(referencedIdp).isNotNull();
        assertThat(referencedIdp.getId()).isNotBlank().isEqualTo(idp.getAliasId());
        assertThat(referencedIdp.getIdentityZoneId()).isNotBlank().isEqualTo(idp.getAliasZid());
    }

    private void assertOtherPropertiesAreEqual(final IdentityProvider<?> idp, final IdentityProvider<?> mirroredIdp) {
        // apart from the zone ID, the configs should be identical
        final SamlIdentityProviderDefinition originalIdpConfig = (SamlIdentityProviderDefinition) idp.getConfig();
        originalIdpConfig.setZoneId(null);
        final SamlIdentityProviderDefinition mirroredIdpConfig = (SamlIdentityProviderDefinition) mirroredIdp.getConfig();
        mirroredIdpConfig.setZoneId(null);
        assertThat(mirroredIdpConfig).isEqualTo(originalIdpConfig);

        // check if remaining properties are equal
        assertThat(mirroredIdp.getOriginKey()).isEqualTo(idp.getOriginKey());
        assertThat(mirroredIdp.getName()).isEqualTo(idp.getName());
        assertThat(mirroredIdp.getType()).isEqualTo(idp.getType());
    }

    private IdentityProvider<?> createMirroredIdp(final IdentityZone zone1, final IdentityZone zone2) throws Exception {
        final IdentityProvider<?> provider = buildIdpWithAliasProperties(zone1.getId(), null, zone2.getId());
        return createIdp(zone1, provider);
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

    private static IdentityProvider<?> buildIdpWithAliasProperties(final String idzId, final String aliasId, final String aliasZid) {
        final String originKey = RandomStringUtils.randomAlphabetic(8);
        return buildIdpWithAliasProperties(idzId, aliasId, aliasZid, originKey);
    }

    private static IdentityProvider<?> buildIdpWithAliasProperties(final String idzId, final String aliasId, final String aliasZid, final String originKey) {
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
