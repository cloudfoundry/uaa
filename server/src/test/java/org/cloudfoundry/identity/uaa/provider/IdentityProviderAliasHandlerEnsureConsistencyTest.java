package org.cloudfoundry.identity.uaa.provider;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
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
import org.cloudfoundry.identity.uaa.alias.EntityAliasHandlerEnsureConsistencyTest;
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
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
public class IdentityProviderAliasHandlerEnsureConsistencyTest extends EntityAliasHandlerEnsureConsistencyTest<IdentityProvider<?>> {
    @Mock
    private IdentityZoneProvisioning identityZoneProvisioning;
    @Mock
    private IdentityProviderProvisioning identityProviderProvisioning;
    private IdentityProviderAliasHandler idpAliasHandler;

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
                final String aliasIdpId = UUID.randomUUID().toString();
                final String originalIdpId = UUID.randomUUID().toString();

                final IdentityProvider<?> existingIdp = new IdentityProvider<>();
                existingIdp.setType(OIDC10);
                existingIdp.setId(originalIdpId);
                existingIdp.setIdentityZoneId(UAA);
                existingIdp.setAliasId(aliasIdpId);
                existingIdp.setAliasZid(customZoneId);

                final IdentityProvider<?> originalIdp = shallowCloneIdp(existingIdp);
                final String newName = "some-new-name";
                originalIdp.setName(newName);

                final IdentityProvider<?> aliasIdp = shallowCloneIdp(existingIdp);
                aliasIdp.setId(aliasIdpId);
                aliasIdp.setIdentityZoneId(customZoneId);
                aliasIdp.setAliasId(originalIdpId);
                aliasIdp.setAliasZid(UAA);
                when(identityProviderProvisioning.retrieve(aliasIdpId, customZoneId)).thenReturn(aliasIdp);

                final IdentityProvider<?> result = idpAliasHandler.ensureConsistencyOfAliasEntity(
                        originalIdp,
                        existingIdp
                );
                assertThat(result).isEqualTo(originalIdp);

                final ArgumentCaptor<IdentityProvider> aliasIdpArgumentCaptor = ArgumentCaptor.forClass(IdentityProvider.class);
                verify(identityProviderProvisioning).update(aliasIdpArgumentCaptor.capture(), eq(customZoneId));

                final IdentityProvider capturedAliasIdp = aliasIdpArgumentCaptor.getValue();
                assertThat(capturedAliasIdp.getAliasId()).isEqualTo(originalIdpId);
                assertThat(capturedAliasIdp.getAliasZid()).isEqualTo(UAA);
                assertThat(capturedAliasIdp.getId()).isEqualTo(aliasIdpId);
                assertThat(capturedAliasIdp.getIdentityZoneId()).isEqualTo(customZoneId);
                assertThat(capturedAliasIdp.getName()).isEqualTo(newName);
            }

            @Test
            void shouldThrow_WhenReferencedAliasIdpAndAliasZoneDoesNotExist() {
                final String aliasIdpId = UUID.randomUUID().toString();
                final String originalIdpId = UUID.randomUUID().toString();

                final IdentityProvider<?> existingIdp = new IdentityProvider<>();
                existingIdp.setType(OIDC10);
                existingIdp.setId(originalIdpId);
                existingIdp.setIdentityZoneId(UAA);
                existingIdp.setAliasId(aliasIdpId);
                existingIdp.setAliasZid(customZoneId);

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

                final IdentityProvider existingIdp = new IdentityProvider<>();
                existingIdp.setType(OIDC10);
                existingIdp.setConfig(new OIDCIdentityProviderDefinition());
                existingIdp.setId(originalIdpId);
                existingIdp.setIdentityZoneId(UAA);
                existingIdp.setAliasId(initialAliasIdpId);
                existingIdp.setAliasZid(customZoneId);

                final IdentityProvider<?> requestBody = shallowCloneIdp(existingIdp);
                final String newName = "some-new-name";
                requestBody.setName(newName);

                // dangling reference -> referenced alias IdP not present
                when(identityProviderProvisioning.retrieve(initialAliasIdpId, customZoneId)).thenReturn(null);

                // mock alias IdP creation
                final IdentityProvider<?> createdAliasIdp = shallowCloneIdp(requestBody);
                final String newAliasIdpId = UUID.randomUUID().toString();
                createdAliasIdp.setId(newAliasIdpId);
                createdAliasIdp.setIdentityZoneId(customZoneId);
                createdAliasIdp.setAliasId(originalIdpId);
                createdAliasIdp.setAliasZid(UAA);
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

                @Override
                public boolean matches(final IdentityProvider<?> argument) {
                    return Objects.equals(id, argument.getId()) && Objects.equals(identityZoneId, argument.getIdentityZoneId())
                            && Objects.equals(aliasId, argument.getAliasId()) && Objects.equals(aliasZid, argument.getAliasZid());
                }
            }
        }

        @Nested
        class AliasFeatureDisabled {
            @BeforeEach
            void setUp() {
                arrangeAliasFeatureEnabled(false);
            }

            @Test
            void shouldThrow_IfExistingEntityHasAlias() {
                final String idpId = UUID.randomUUID().toString();
                final String aliasIdpId = UUID.randomUUID().toString();

                final IdentityProvider<?> existingIdp = new IdentityProvider<>();
                existingIdp.setType(OIDC10);
                existingIdp.setId(idpId);
                existingIdp.setIdentityZoneId(UAA);
                existingIdp.setAliasId(aliasIdpId);
                existingIdp.setAliasZid(customZoneId);

                final IdentityProvider<?> originalIdp = shallowCloneIdp(existingIdp);
                originalIdp.setAliasId(null);
                originalIdp.setAliasZid(null);
                originalIdp.setName("some-new-name");

                assertThatIllegalStateException().isThrownBy(() ->
                        idpAliasHandler.ensureConsistencyOfAliasEntity(originalIdp, existingIdp)
                ).withMessage("Performing update on entity with alias while alias feature is disabled.");
            }
        }
    }

    @Nested
    class NoExistingAlias {
        abstract class NoExistingAliasBase {
            @Test
            void shouldIgnore_AliasZidEmptyInOriginalIdp() {
                final IdentityProvider<?> existingIdp = new IdentityProvider<>();
                existingIdp.setType(OIDC10);
                final String idpId = UUID.randomUUID().toString();
                existingIdp.setId(idpId);
                existingIdp.setIdentityZoneId(UAA);
                existingIdp.setAliasId(null);
                existingIdp.setAliasZid(null);

                final IdentityProvider<?> originalIdp = shallowCloneIdp(existingIdp);
                originalIdp.setName("some-new-name");

                final IdentityProvider<?> result = idpAliasHandler.ensureConsistencyOfAliasEntity(originalIdp, existingIdp);
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
                final IdentityProvider<?> existingIdp = new IdentityProvider<>();
                existingIdp.setType(OIDC10);
                final String idpId = UUID.randomUUID().toString();
                existingIdp.setId(idpId);
                existingIdp.setIdentityZoneId(UAA);
                existingIdp.setAliasId(null);
                existingIdp.setAliasZid(null);

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
                final IdentityProvider<?> existingIdp = new IdentityProvider<>();
                existingIdp.setType(OIDC10);
                final String idpId = UUID.randomUUID().toString();
                existingIdp.setId(idpId);
                existingIdp.setIdentityZoneId(UAA);
                existingIdp.setAliasId(null);
                existingIdp.setAliasZid(null);

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
}
