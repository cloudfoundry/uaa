package org.cloudfoundry.identity.uaa.provider;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Objects;
import java.util.UUID;

import org.cloudfoundry.identity.uaa.alias.EntityAliasFailedException;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.ZoneDoesNotExistsException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatcher;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
public class IdentityProviderAliasHandlerEnsureConsistencyTest {
    @Mock
    private IdentityZoneProvisioning identityZoneProvisioning;
    @Mock
    private IdentityProviderProvisioning identityProviderProvisioning;
    private IdentityProviderAliasHandler idpAliasHandler;

    private final String customZoneId = UUID.randomUUID().toString();

    @BeforeEach
    void setUp() {
        idpAliasHandler = new IdentityProviderAliasHandler(
                identityZoneProvisioning,
                identityProviderProvisioning,
                false
        );
    }

    @Nested
    class ExistingAlias {
        @Nested
        class AliasFeatureEnabled {
            @BeforeEach
            void setUp() {
                arrangeAliasFeatureEnabled(true);
            }

            @Test
            void shouldPropagateChangesToExistingAlias() {
                final String originalIdpId = UUID.randomUUID().toString();
                final String aliasIdpId = UUID.randomUUID().toString();

                // existing IdP with a referenced alias IdP
                final IdentityProvider<OIDCIdentityProviderDefinition> existingIdp = buildIdpWithAlias(
                        originalIdpId,
                        UAA,
                        aliasIdpId,
                        customZoneId
                );

                // alias IdP referencing the original IdP
                final IdentityProvider<?> existingAliasIdp = buildAliasIdp(existingIdp);
                when(identityProviderProvisioning.retrieve(aliasIdpId, customZoneId)).thenReturn(existingAliasIdp);

                // change the name of the IdP (should be propagated to the alias IdP)
                final IdentityProvider<?> requestBody = shallowCloneIdp(existingIdp);
                final String newName = "some-new-name";
                requestBody.setName(newName);

                when(identityProviderProvisioning.update(argThat(new IdpWithAliasMatcher(existingAliasIdp)), eq(customZoneId)))
                        .then(invocationOnMock -> invocationOnMock.getArgument(0));

                final IdentityProvider<?> result = idpAliasHandler.ensureConsistencyOfAliasEntity(
                        requestBody,
                        existingIdp
                );

                // the expected updated alias IdP (with updated name)
                final IdentityProvider<?> updatedAliasIdp = shallowCloneIdp(existingAliasIdp);
                updatedAliasIdp.setName(newName);

                assertThat(result).isNotNull();
                assertIdpsAreEqualApartFromTimestamps(requestBody, result);
            }

            @Test
            void shouldThrow_WhenReferencedAliasIdpAndAliasZoneDoesNotExist() {
                final String aliasIdpId = UUID.randomUUID().toString();
                final String originalIdpId = UUID.randomUUID().toString();

                final IdentityProvider<?> existingIdp = buildIdpWithAlias(
                        originalIdpId,
                        UAA,
                        aliasIdpId,
                        customZoneId
                );

                final IdentityProvider<?> originalIdp = shallowCloneIdp(existingIdp);
                final String newName = "some-new-name";
                originalIdp.setName(newName);

                // dangling reference -> referenced alias IdP not present
                when(identityProviderProvisioning.retrieve(aliasIdpId, customZoneId)).thenReturn(null);

                // alias zone does not exist
                when(identityZoneProvisioning.retrieve(customZoneId))
                        .thenThrow(new ZoneDoesNotExistsException("zone does not exist"));

                assertThatExceptionOfType(EntityAliasFailedException.class).isThrownBy(() ->
                        idpAliasHandler.ensureConsistencyOfAliasEntity(originalIdp, existingIdp)
                );
            }

            @Test
            void shouldFixDanglingReferenceByCreatingNewAliasIdp() {
                final String initialAliasIdpId = UUID.randomUUID().toString();
                final String originalIdpId = UUID.randomUUID().toString();

                final IdentityProvider<?> existingIdp = buildIdpWithAlias(
                        originalIdpId,
                        UAA,
                        initialAliasIdpId,
                        customZoneId
                );

                final IdentityProvider<?> requestBody = shallowCloneIdp(existingIdp);
                final String newName = "some-new-name";
                requestBody.setName(newName);

                // dangling reference -> referenced alias IdP not present
                when(identityProviderProvisioning.retrieve(initialAliasIdpId, customZoneId)).thenReturn(null);

                // mock alias IdP creation
                final IdentityProvider<?> createdAliasIdp = buildAliasIdp(existingIdp);
                final String newAliasIdpId = UUID.randomUUID().toString();
                createdAliasIdp.setId(newAliasIdpId);
                when(identityProviderProvisioning.create(
                        argThat(new IdpWithAliasMatcher(customZoneId, null, originalIdpId, UAA)),
                        eq(customZoneId)
                )).thenReturn(createdAliasIdp);

                // mock update of original IdP
                when(identityProviderProvisioning.update(argThat(new IdpWithAliasMatcher(UAA, originalIdpId, newAliasIdpId, customZoneId)), eq(UAA)))
                        .then(invocationOnMock -> invocationOnMock.getArgument(0));

                final IdentityProvider<?> result = idpAliasHandler.ensureConsistencyOfAliasEntity(
                        requestBody,
                        existingIdp
                );
                assertThat(result.getAliasId()).isEqualTo(newAliasIdpId);
                assertThat(result.getAliasZid()).isEqualTo(customZoneId);

                // should update original IdP with new aliasId
                final ArgumentCaptor<IdentityProvider> originalIdpCaptor = ArgumentCaptor.forClass(IdentityProvider.class);
                verify(identityProviderProvisioning).update(originalIdpCaptor.capture(), eq(UAA));
                final IdentityProvider<?> updatedOriginalIdp = originalIdpCaptor.getValue();
                assertThat(updatedOriginalIdp.getAliasId()).isEqualTo(newAliasIdpId);
            }
        }

        @Nested
        class AliasFeatureDisabled {
            @BeforeEach
            void setUp() {
                arrangeAliasFeatureEnabled(false);
            }

            @Test
            void shouldIgnoreDanglingReferenceInExistingEntity_AliasIdEmpty() {
                final IdentityProvider<?> existingIdp = buildIdpWithAlias(
                        UUID.randomUUID().toString(),
                        UAA,
                        null, // dangling reference: aliasId empty
                        customZoneId
                );

                final IdentityProvider<?> originalIdp = shallowCloneIdp(existingIdp);
                originalIdp.setAliasId(null);
                originalIdp.setAliasZid(null);

                // should ignore dangling reference
                assertThat(idpAliasHandler.ensureConsistencyOfAliasEntity(originalIdp, existingIdp))
                        .isEqualTo(originalIdp);
            }

            @Test
            void shouldIgnoreDanglingReference_AliasNotFound() {
                final String idpId = UUID.randomUUID().toString();
                final String aliasIdpId = UUID.randomUUID().toString();

                final IdentityProvider<?> existingIdp = buildIdpWithAlias(idpId, UAA, aliasIdpId, customZoneId);

                final IdentityProvider<?> originalIdp = shallowCloneIdp(existingIdp);
                originalIdp.setAliasId(null);
                originalIdp.setAliasZid(null);

                // dangling reference: alias IdP does not exist
                when(identityProviderProvisioning.retrieve(aliasIdpId, customZoneId))
                        .thenThrow(new EmptyResultDataAccessException(1));

                // should ignore dangling reference
                assertThat(idpAliasHandler.ensureConsistencyOfAliasEntity(originalIdp, existingIdp))
                        .isEqualTo(originalIdp);
            }

            @Test
            void shouldBreakReferenceInAliasIdp() {
                final String idpId = UUID.randomUUID().toString();
                final String aliasIdpId = UUID.randomUUID().toString();

                final IdentityProvider<?> existingIdp = buildIdpWithAlias(idpId, UAA, aliasIdpId, customZoneId);

                final IdentityProvider<?> aliasIdp = buildAliasIdp(existingIdp);
                when(identityProviderProvisioning.retrieve(aliasIdpId, customZoneId)).thenReturn(aliasIdp);

                final IdentityProvider<?> requestBody = shallowCloneIdp(existingIdp);
                requestBody.setAliasId(null);
                requestBody.setAliasZid(null);
                idpAliasHandler.ensureConsistencyOfAliasEntity(requestBody, existingIdp);

                final IdentityProvider<?> aliasIdpWithEmptyAliasProps = shallowCloneIdp(aliasIdp);
                aliasIdpWithEmptyAliasProps.setAliasZid(null);
                aliasIdpWithEmptyAliasProps.setAliasId(null);

                // should break reference in alias IdP
                verify(identityProviderProvisioning).update(aliasIdpWithEmptyAliasProps, customZoneId);
            }
        }
    }

    @Nested
    class NoExistingAlias {

        abstract class NoExistingAliasBase {
            @Test
            void shouldIgnore_AliasZidEmptyInOriginalIdp() {
                final String idpId = UUID.randomUUID().toString();
                final IdentityProvider<?> existingIdp = buildIdpWithAlias(idpId, UAA, null, null);

                final IdentityProvider<?> originalIdp = shallowCloneIdp(existingIdp);
                originalIdp.setName("some-new-name");

                final IdentityProvider<?> result = idpAliasHandler.ensureConsistencyOfAliasEntity(
                        originalIdp,
                        existingIdp
                );
                assertThat(result).isEqualTo(originalIdp);
            }
        }
        @Nested
        class AliasFeatureEnabled extends NoExistingAliasBase {
            @BeforeEach
            void setUp() {
                arrangeAliasFeatureEnabled(true);
            }

            @Test
            void shouldThrow_WhenAliasZoneDoesNotExist() {
                final String idpId = UUID.randomUUID().toString();
                final IdentityProvider<?> existingIdp = buildIdpWithAlias(idpId, UAA, null, null);

                final IdentityProvider<?> requestBody = shallowCloneIdp(existingIdp);
                requestBody.setAliasZid(customZoneId);

                when(identityZoneProvisioning.retrieve(customZoneId))
                        .thenThrow(new ZoneDoesNotExistsException("zone does not exist"));

                assertThatExceptionOfType(EntityAliasFailedException.class).isThrownBy(() ->
                        idpAliasHandler.ensureConsistencyOfAliasEntity(requestBody, existingIdp)
                );
            }

            @Test
            void shouldCreateNewAliasIdp_WhenAliasZoneExistsAndAliasPropertiesAreSet() {
                final String idpId = UUID.randomUUID().toString();
                final IdentityProvider<?> existingIdp = buildIdpWithAlias(idpId, UAA, null, null);

                final IdentityProvider<?> requestBody = shallowCloneIdp(existingIdp);
                requestBody.setAliasZid(customZoneId);

                final String aliasIdpId = UUID.randomUUID().toString();
                when(identityProviderProvisioning.create(any(), eq(customZoneId))).then(invocationOnMock -> {
                    final IdentityProvider<?> idp = invocationOnMock.getArgument(0);
                    idp.setId(aliasIdpId);
                    return idp;
                });

                when(identityProviderProvisioning.update(any(), eq(UAA)))
                        .then(invocationOnMock -> invocationOnMock.getArgument(0));

                final IdentityProvider<?> result = idpAliasHandler.ensureConsistencyOfAliasEntity(
                        requestBody,
                        existingIdp
                );
                assertThat(result.getAliasId()).isEqualTo(aliasIdpId);
                assertThat(result.getAliasZid()).isEqualTo(customZoneId);
            }
        }

        @Nested
        class AliasFeatureDisabled extends NoExistingAliasBase {
            @BeforeEach
            void setUp() {
                arrangeAliasFeatureEnabled(false);
            }
        }
    }

    private void arrangeAliasFeatureEnabled(final boolean enabled) {
        ReflectionTestUtils.setField(idpAliasHandler, "aliasEntitiesEnabled", enabled);
    }

    private static <T extends AbstractIdentityProviderDefinition> IdentityProvider<T> shallowCloneIdp(
            final IdentityProvider<T> idp
    ) {
        final IdentityProvider<T> cloneIdp = new IdentityProvider<>();
        cloneIdp.setId(idp.getId());
        cloneIdp.setName(idp.getName());
        cloneIdp.setOriginKey(idp.getOriginKey());
        cloneIdp.setConfig(idp.getConfig());
        cloneIdp.setType(idp.getType());
        cloneIdp.setCreated(idp.getCreated());
        cloneIdp.setLastModified(idp.getLastModified());
        cloneIdp.setIdentityZoneId(idp.getIdentityZoneId());
        cloneIdp.setAliasId(idp.getAliasId());
        cloneIdp.setAliasZid(idp.getAliasZid());
        cloneIdp.setActive(idp.isActive());
        assertThat(cloneIdp).isEqualTo(idp);
        return cloneIdp;
    }

    private static void assertIdpsAreEqualApartFromTimestamps(
            final IdentityProvider<?> expected,
            final IdentityProvider<?> actual
    ) {
        // the configs should be identical
        assertThat(actual.getConfig()).isEqualTo(expected.getConfig());

        // check if remaining properties are equal
        assertThat(actual.getOriginKey()).isEqualTo(expected.getOriginKey());
        assertThat(actual.getName()).isEqualTo(expected.getName());
        assertThat(actual.getType()).isEqualTo(expected.getType());
        assertThat(actual.isActive()).isEqualTo(expected.isActive());

        // it is expected that the two entities have differing values for 'lastmodified', 'created' and 'version'
    }

    private static IdentityProvider<OIDCIdentityProviderDefinition> buildIdpWithAlias(
            final String id,
            final String zoneId,
            final String aliasId,
            final String aliasZid
    ) {
        final IdentityProvider<OIDCIdentityProviderDefinition> existingIdp = new IdentityProvider<>();
        existingIdp.setType(OIDC10);
        existingIdp.setConfig(new OIDCIdentityProviderDefinition());
        existingIdp.setId(id);
        existingIdp.setIdentityZoneId(zoneId);
        existingIdp.setAliasId(aliasId);
        existingIdp.setAliasZid(aliasZid);
        return existingIdp;
    }

    private static IdentityProvider<?> buildAliasIdp(final IdentityProvider<?> originalIdp) {
        final IdentityProvider<?> aliasIdp = shallowCloneIdp(originalIdp);
        assertThat(originalIdp.getAliasId()).isNotBlank();
        aliasIdp.setId(originalIdp.getAliasId());
        assertThat(originalIdp.getAliasZid()).isNotBlank();
        aliasIdp.setIdentityZoneId(originalIdp.getAliasZid());
        aliasIdp.setAliasId(originalIdp.getId());
        aliasIdp.setAliasZid(originalIdp.getIdentityZoneId());
        return aliasIdp;
    }

    private static class IdpWithAliasMatcher implements ArgumentMatcher<IdentityProvider<?>> {
        private final String identityZoneId;
        private final String id;
        private final String aliasId;
        private final String aliasZid;

        public IdpWithAliasMatcher(final String identityZoneId, final String id, final String aliasId, final String aliasZid) {
            this.identityZoneId = identityZoneId;
            this.id = id;
            this.aliasId = aliasId;
            this.aliasZid = aliasZid;
        }

        public IdpWithAliasMatcher(final IdentityProvider<?> idp) {
            this(idp.getIdentityZoneId(), idp.getId(), idp.getAliasId(), idp.getAliasZid());
        }

        @Override
        public boolean matches(final IdentityProvider<?> argument) {
            return Objects.equals(id, argument.getId()) && Objects.equals(identityZoneId, argument.getIdentityZoneId())
                    && Objects.equals(aliasId, argument.getAliasId()) && Objects.equals(aliasZid, argument.getAliasZid());
        }
    }
}
