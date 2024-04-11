package org.cloudfoundry.identity.uaa.provider;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Objects;
import java.util.UUID;

import org.cloudfoundry.identity.uaa.alias.EntityAliasHandler;
import org.cloudfoundry.identity.uaa.alias.EntityAliasHandlerEnsureConsistencyTest;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.ZoneDoesNotExistsException;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class IdentityProviderAliasHandlerEnsureConsistencyTest extends EntityAliasHandlerEnsureConsistencyTest<IdentityProvider<?>> {
    @Mock
    private IdentityZoneProvisioning identityZoneProvisioning;
    @Mock
    private IdentityProviderProvisioning identityProviderProvisioning;

    @Override
    protected EntityAliasHandler<IdentityProvider<?>> buildAliasHandler(final boolean aliasEntitiesEnabled) {
        return new IdentityProviderAliasHandler(
                identityZoneProvisioning,
                identityProviderProvisioning,
                aliasEntitiesEnabled
        );
    }

    @Nested
    class ExistingAlias {
        @Nested
        class AliasFeatureEnabled extends ExistingAlias_AliasFeatureEnabled {
            @Test
            void shouldPropagateChangesToExistingAlias() {
                final String aliasIdpId = UUID.randomUUID().toString();
                final IdentityProvider<?> existingIdp = buildEntityWithAliasProperties(aliasIdpId, customZoneId);

                final IdentityProvider<?> originalIdp = shallowCloneEntity(existingIdp);
                final String newName = "some-new-name";
                originalIdp.setName(newName);

                // arrange alias IdP is present
                final IdentityProvider<?> aliasIdp = shallowCloneEntity(existingIdp);
                aliasIdp.setId(existingIdp.getAliasId());
                aliasIdp.setIdentityZoneId(existingIdp.getAliasZid());
                aliasIdp.setAliasId(existingIdp.getId());
                aliasIdp.setAliasZid(existingIdp.getZoneId());
                arrangeEntityExists(aliasIdp.getId(), aliasIdp.getZoneId(), aliasIdp);

                final IdentityProvider<?> result = aliasHandler.ensureConsistencyOfAliasEntity(
                        originalIdp,
                        existingIdp
                );
                assertThat(result).isEqualTo(originalIdp);

                // check if the change was propagated to the alias IdP
                final ArgumentCaptor<IdentityProvider> aliasIdpArgumentCaptor = ArgumentCaptor.forClass(IdentityProvider.class);
                verify(identityProviderProvisioning).update(aliasIdpArgumentCaptor.capture(), eq(customZoneId));
                final IdentityProvider capturedAliasIdp = aliasIdpArgumentCaptor.getValue();
                assertThat(capturedAliasIdp.getAliasId()).isEqualTo(existingIdp.getId());
                assertThat(capturedAliasIdp.getAliasZid()).isEqualTo(UAA);
                assertThat(capturedAliasIdp.getId()).isEqualTo(aliasIdpId);
                assertThat(capturedAliasIdp.getIdentityZoneId()).isEqualTo(customZoneId);
                assertThat(capturedAliasIdp.getName()).isEqualTo(newName);
            }

            @Test
            void shouldFixDanglingReferenceByCreatingNewAliasIdp() {
                final String initialAliasIdpId = UUID.randomUUID().toString();
                final IdentityProvider<?> existingIdp = buildEntityWithAliasProperties(initialAliasIdpId, customZoneId);
                final String originalIdpId = existingIdp.getId();

                final IdentityProvider<?> requestBody = shallowCloneEntity(existingIdp);
                final String newName = "some-new-name";
                requestBody.setName(newName);

                // dangling reference -> referenced alias IdP not present
                arrangeEntityDoesNotExist(initialAliasIdpId, customZoneId);

                // mock creation of new alias IdP
                final IdentityProvider<?> createdAliasIdp = shallowCloneEntity(requestBody);
                final String newAliasIdpId = UUID.randomUUID().toString();
                createdAliasIdp.setId(newAliasIdpId);
                createdAliasIdp.setIdentityZoneId(customZoneId);
                createdAliasIdp.setAliasId(originalIdpId);
                createdAliasIdp.setAliasZid(UAA);
                when(identityProviderProvisioning.create(
                        argThat(new EntityWithAliasMatcher<IdentityProvider<?>>(customZoneId, null, originalIdpId, UAA)),
                        eq(customZoneId)
                )).thenReturn(createdAliasIdp);

                // mock update of original IdP
                when(identityProviderProvisioning.update(
                        argThat(new EntityWithAliasMatcher<IdentityProvider<?>>(UAA, originalIdpId, newAliasIdpId, customZoneId)),
                        eq(UAA)
                )).then(invocationOnMock -> invocationOnMock.getArgument(0));

                // check if the original IdP now references the new alias
                final IdentityProvider<?> result = aliasHandler.ensureConsistencyOfAliasEntity(
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
        class AliasFeatureDisabled extends ExistingAlias_AliasFeatureDisabled {
            // all tests defined in superclass
        }
    }

    @Nested
    class NoExistingAlias {
        @Nested
        class AliasFeatureEnabled extends NoExistingAlias_AliasFeatureEnabled {
            // all tests defined in superclass
        }

        @Nested
        class AliasFeatureDisabled extends NoExistingAlias_AliasFeatureDisabled {
            // all tests defined in superclass
        }
    }

    @Override
    protected IdentityProvider<?> shallowCloneEntity(final IdentityProvider<?> idp) {
        final IdentityProvider<AbstractIdentityProviderDefinition> cloneIdp = new IdentityProvider<>();
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

    @Override
    protected IdentityProvider<?> buildEntityWithAliasProperties(final String aliasId, final String aliasZid) {
        final IdentityProvider<?> existingIdp = new IdentityProvider<>();
        existingIdp.setType(OIDC10);
        existingIdp.setId(UUID.randomUUID().toString());
        existingIdp.setIdentityZoneId(UAA);
        existingIdp.setAliasId(aliasId);
        existingIdp.setAliasZid(aliasZid);
        return existingIdp;
    }

    @Override
    protected void changeNonAliasProperties(final IdentityProvider<?> entity) {
        entity.setName("some-new-name");
    }

    @Override
    protected void arrangeZoneDoesNotExist(final String zoneId) {
        when(identityZoneProvisioning.retrieve(zoneId))
                .thenThrow(new ZoneDoesNotExistsException("zone does not exist"));
    }

    @Override
    protected void mockUpdateEntity(final String zoneId) {
        when(identityProviderProvisioning.update(any(), eq(zoneId)))
                .then(invocationOnMock -> invocationOnMock.getArgument(0));
    }

    @Override
    protected void mockCreateEntity(final String newId, final String zoneId) {
        when(identityProviderProvisioning.create(any(), eq(customZoneId))).then(invocationOnMock -> {
            final IdentityProvider<?> idp = invocationOnMock.getArgument(0);
            idp.setId(newId);
            return idp;
        });
    }

    @Override
    protected void arrangeEntityExists(final String id, final String zoneId, final IdentityProvider<?> entity) {
        when(identityProviderProvisioning.retrieve(id, zoneId)).thenReturn(entity);
    }

    @Override
    protected void arrangeEntityDoesNotExist(final String id, final String zoneId) {
        when(identityProviderProvisioning.retrieve(id, zoneId)).thenReturn(null);
    }

    @Override
    protected boolean entitiesAreEqual(final IdentityProvider<?> entity1, final IdentityProvider<?> entity2) {
        return Objects.equals(entity1, entity2);
    }
}
