package org.cloudfoundry.identity.uaa.scim;

import org.cloudfoundry.identity.uaa.alias.EntityAliasFailedException;
import org.cloudfoundry.identity.uaa.alias.EntityAliasHandler;
import org.cloudfoundry.identity.uaa.alias.EntityAliasHandlerEnsureConsistencyTest;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.ZoneDoesNotExistsException;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;

import java.sql.Timestamp;
import java.util.Collections;
import java.util.Date;
import java.util.Objects;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ScimUserAliasHandlerEnsureConsistencyTest extends EntityAliasHandlerEnsureConsistencyTest<ScimUser> {
    @Mock
    private ScimUserProvisioning scimUserProvisioning;
    @Mock
    private IdentityProviderProvisioning identityProviderProvisioning;
    @Mock
    private IdentityZoneManager identityZoneManager;
    @Mock
    private IdentityZoneProvisioning identityZoneProvisioning;

    @Override
    protected EntityAliasHandler<ScimUser> buildAliasHandler(final boolean aliasEntitiesEnabled) {
        return new ScimUserAliasHandler(
                identityZoneProvisioning,
                scimUserProvisioning,
                identityProviderProvisioning,
                identityZoneManager,
                aliasEntitiesEnabled
        );
    }

    @Override
    protected ScimUser shallowCloneEntity(final ScimUser entity) {
        final ScimUser clonedScimUser = new ScimUser();
        clonedScimUser.setId(entity.getId());
        clonedScimUser.setUserName(entity.getUserName());
        clonedScimUser.setPrimaryEmail(entity.getPrimaryEmail());
        clonedScimUser.setName(entity.getName());
        clonedScimUser.setActive(entity.isActive());
        clonedScimUser.setPhoneNumbers(entity.getPhoneNumbers());
        clonedScimUser.setOrigin(entity.getOrigin());
        clonedScimUser.setAliasId(entity.getAliasId());
        clonedScimUser.setAliasZid(entity.getAliasZid());
        clonedScimUser.setZoneId(entity.getZoneId());
        clonedScimUser.setPassword(entity.getPassword());
        clonedScimUser.setSalt(entity.getSalt());
        return clonedScimUser;
    }

    @Override
    protected ScimUser buildEntityWithAliasProperties(String aliasId, String aliasZid) {
        final ScimUser scimUser = new ScimUser();
        scimUser.setId(UUID.randomUUID().toString());
        scimUser.setUserName("john.doe");
        scimUser.setPrimaryEmail("john.doe@example.com");
        scimUser.setName(new ScimUser.Name("John", "Doe"));
        scimUser.setActive(true);
        scimUser.setPhoneNumbers(Collections.singletonList(new ScimUser.PhoneNumber("12345")));
        scimUser.setOrigin("some-origin");
        scimUser.setAliasId(aliasId);
        scimUser.setAliasZid(aliasZid);
        scimUser.setZoneId(UAA);
        scimUser.setPassword("");
        scimUser.setSalt(null);
        return scimUser;
    }

    @Override
    protected boolean entitiesAreEqual(final ScimUser entity1, final ScimUser entity2) {
        return Objects.equals(entity1.getId(), entity2.getId())
                && Objects.equals(entity1.getUserName(), entity2.getUserName())
                && Objects.equals(entity1.getPrimaryEmail(), entity2.getPrimaryEmail())
                && Objects.equals(entity1.getGivenName(), entity2.getGivenName())
                && Objects.equals(entity1.getFamilyName(), entity2.getFamilyName())
                && Objects.equals(entity1.isActive(), entity2.isActive())
                && Objects.equals(entity1.getPhoneNumbers(), entity2.getPhoneNumbers())
                && Objects.equals(entity1.getOrigin(), entity2.getOrigin())
                && Objects.equals(entity1.getAliasId(), entity2.getAliasId())
                && Objects.equals(entity1.getAliasZid(), entity2.getAliasZid())
                && Objects.equals(entity1.getZoneId(), entity2.getZoneId())
                && Objects.equals(entity1.getPassword(), entity2.getPassword())
                && Objects.equals(entity1.getSalt(), entity2.getSalt())
                && Objects.equals(entity1.getPreviousLogonTime(), entity2.getPreviousLogonTime())
                && Objects.equals(entity1.getLastLogonTime(), entity2.getLastLogonTime())
                && Objects.equals(entity1.getPasswordLastModified(), entity2.getPasswordLastModified());
    }

    @Override
    protected void changeNonAliasProperties(final ScimUser entity) {
        entity.getName().setGivenName("some-new-given-name");
    }

    @Override
    protected void arrangeZoneDoesNotExist(final String zoneId) {
        when(identityZoneProvisioning.retrieve(zoneId))
                .thenThrow(new ZoneDoesNotExistsException("zone does not exist"));
    }

    @Override
    protected void mockUpdateEntity(final String zoneId) {
        when(scimUserProvisioning.update(any(), any(), eq(zoneId)))
                .then(invocationOnMock -> invocationOnMock.getArgument(1));
    }

    @Override
    protected void mockCreateEntity(final String newId, final String zoneId) {
        when(scimUserProvisioning.createUser(any(), anyString(), eq(zoneId))).then(invocationOnMock -> {
            final ScimUser scimUser = invocationOnMock.getArgument(0);
            scimUser.setId(newId);
            return scimUser;
        });
    }

    private void mockCreateEntityThrows_UsernameAlreadyOccupied(final String username, final String zoneId) {
        when(scimUserProvisioning.createUser(
                argThat(scimUser -> Objects.equals(username, scimUser.getUserName())),
                anyString(),
                eq(zoneId)
        )).thenThrow(new ScimResourceAlreadyExistsException("username already occupied"));
    }

    @Override
    protected void arrangeEntityExists(final String id, final String zoneId, final ScimUser entity) {
        when(scimUserProvisioning.retrieve(id, zoneId)).thenReturn(entity);
    }

    @Override
    protected void arrangeEntityDoesNotExist(final String id, final String zoneId) {
        when(scimUserProvisioning.retrieve(id, zoneId)).thenThrow(new ScimResourceNotFoundException("user not found"));
    }

    @Nested
    class ExistingAlias {
        @Nested
        class AliasFeatureEnabled extends ExistingAlias_AliasFeatureEnabled {
            @Test
            void shouldPropagateChangesToExistingAlias() {
                final String aliasId = UUID.randomUUID().toString();
                final ScimUser existingUser = buildEntityWithAliasProperties(aliasId, customZoneId);

                // set timestamps of original user
                final Timestamp timestampOriginalUser = new Timestamp(new Date().getTime());
                existingUser.setPasswordLastModified(timestampOriginalUser);
                existingUser.setPreviousLogonTime(timestampOriginalUser.getTime());
                existingUser.setLastLogonTime(timestampOriginalUser.getTime());

                final ScimUser originalUser = shallowCloneEntity(existingUser);
                final String newGivenName = "some-new-name";
                originalUser.setName(new ScimUser.Name(newGivenName, originalUser.getFamilyName()));

                // arrange alias user is present
                final ScimUser aliasUser = shallowCloneEntity(existingUser);
                aliasUser.setId(existingUser.getAliasId());
                aliasUser.setZoneId(existingUser.getAliasZid());
                aliasUser.setAliasId(existingUser.getId());
                aliasUser.setAliasZid(existingUser.getZoneId());

                // set timestamps of alias user to a different value
                final Timestamp timestampAliasUser = new Timestamp(new Date().getTime() + 5000);
                aliasUser.setPasswordLastModified(timestampAliasUser);
                aliasUser.setPreviousLogonTime(timestampAliasUser.getTime());
                aliasUser.setLastLogonTime(timestampAliasUser.getTime());

                arrangeEntityExists(aliasUser.getId(), aliasUser.getZoneId(), aliasUser);

                final ScimUser result = aliasHandler.ensureConsistencyOfAliasEntity(
                        originalUser,
                        existingUser
                );
                assertThat(entitiesAreEqual(result, originalUser)).isTrue();

                // check if the change was propagated to the alias user
                final ArgumentCaptor<ScimUser> userArgCaptor = ArgumentCaptor.forClass(ScimUser.class);
                verify(scimUserProvisioning).update(eq(aliasId), userArgCaptor.capture(), eq(customZoneId));
                final ScimUser capturedUser = userArgCaptor.getValue();
                assertThat(capturedUser.getAliasId()).isEqualTo(existingUser.getId());
                assertThat(capturedUser.getAliasZid()).isEqualTo(UAA);
                assertThat(capturedUser.getId()).isEqualTo(aliasId);
                assertThat(capturedUser.getZoneId()).isEqualTo(customZoneId);
                assertThat(capturedUser.getGivenName()).isEqualTo(newGivenName);

                // check if the alias timestamps were left unchanged even though the original user has different ones
                assertThat(capturedUser.getPasswordLastModified()).isNotNull().isEqualTo(timestampAliasUser);
                assertThat(capturedUser.getPreviousLogonTime()).isNotNull().isEqualTo(timestampAliasUser.getTime());
                assertThat(capturedUser.getLastLogonTime()).isNotNull().isEqualTo(timestampAliasUser.getTime());
            }

            @Test
            void shouldFixDanglingReferenceByCreatingNewAliasEntity() {
                final String initialAliasId = UUID.randomUUID().toString();
                final ScimUser existingUser = buildEntityWithAliasProperties(initialAliasId, customZoneId);
                final String originalUserId = existingUser.getId();

                final ScimUser requestBody = shallowCloneEntity(existingUser);
                final String newGivenName = "some-new-given-name";
                requestBody.setName(new ScimUser.Name(newGivenName, requestBody.getFamilyName()));

                // dangling reference -> referenced alias user not present
                arrangeEntityDoesNotExist(initialAliasId, customZoneId);

                // mock creation of new alias user
                final ScimUser createdAliasUser = shallowCloneEntity(requestBody);
                final String newAliasUserId = UUID.randomUUID().toString();
                createdAliasUser.setId(newAliasUserId);
                createdAliasUser.setZoneId(customZoneId);
                createdAliasUser.setAliasId(originalUserId);
                createdAliasUser.setAliasZid(UAA);
                when(scimUserProvisioning.createUser(
                        argThat(new EntityWithAliasMatcher<>(customZoneId, null, originalUserId, UAA)),
                        eq(UaaStringUtils.EMPTY_STRING),
                        eq(customZoneId)
                )).thenReturn(createdAliasUser);

                // mock update of original user
                when(scimUserProvisioning.update(
                        eq(originalUserId),
                        argThat(new EntityWithAliasMatcher<>(UAA, originalUserId, newAliasUserId, customZoneId)),
                        eq(UAA)
                )).then(invocationOnMock -> invocationOnMock.getArgument(1));

                // check if the original user now references the new alias
                final ScimUser result = aliasHandler.ensureConsistencyOfAliasEntity(
                        requestBody,
                        existingUser
                );
                assertThat(result.getAliasId()).isEqualTo(newAliasUserId);
                assertThat(result.getAliasZid()).isEqualTo(customZoneId);

                // should update original user with new aliasId
                final ArgumentCaptor<ScimUser> originalUserCaptor = ArgumentCaptor.forClass(ScimUser.class);
                verify(scimUserProvisioning).update(eq(originalUserId), originalUserCaptor.capture(), eq(UAA));
                final ScimUser capturedOriginalUser = originalUserCaptor.getValue();
                assertThat(capturedOriginalUser.getAliasId()).isEqualTo(newAliasUserId);
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
            @Test
            void shouldThrow_WhenUsernameAlreadyOccupiedInAliasZone() {
                final ScimUser existingEntity = buildEntityWithAliasProperties(null, null);
                final ScimUser originalEntity = shallowCloneEntity(existingEntity);
                originalEntity.setAliasZid(customZoneId);

                mockCreateEntityThrows_UsernameAlreadyOccupied(originalEntity.getUserName(), customZoneId);

                assertThatThrownBy(() -> aliasHandler.ensureConsistencyOfAliasEntity(originalEntity, existingEntity))
                        .isInstanceOf(EntityAliasFailedException.class)
                        .hasMessage("Could not create ScimUser[id=null,zid='%s',aliasId='%s',aliasZid='uaa']. A user with the same username already exists in the alias zone."
                                .formatted(customZoneId, existingEntity.getId()))
                        .satisfies(e -> assertThat(((EntityAliasFailedException) e).getHttpStatus()).isEqualTo(HttpStatus.CONFLICT.value()));
            }
        }

        @Nested
        class AliasFeatureDisabled extends NoExistingAlias_AliasFeatureDisabled {
            // all tests defined in superclass
        }
    }
}
