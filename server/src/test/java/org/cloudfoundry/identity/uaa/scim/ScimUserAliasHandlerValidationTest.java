package org.cloudfoundry.identity.uaa.scim;

import org.cloudfoundry.identity.uaa.alias.EntityAliasHandler;
import org.cloudfoundry.identity.uaa.alias.EntityAliasHandlerValidationTest;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.ZoneDoesNotExistsException;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.EmptyResultDataAccessException;

import java.util.Collections;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ScimUserAliasHandlerValidationTest extends EntityAliasHandlerValidationTest<ScimUser> {
    private static final AlphanumericRandomValueStringGenerator RANDOM_STRING_GENERATOR = new AlphanumericRandomValueStringGenerator(5);

    @Mock
    private IdentityZoneProvisioning identityZoneProvisioning;
    @Mock
    private ScimUserProvisioning scimUserProvisioning;
    @Mock
    private IdentityProviderProvisioning identityProviderProvisioning;
    @Mock
    private IdentityZoneManager identityZoneManager;

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
    protected ScimUser buildEntityWithAliasProps(final String zoneId, final String aliasId, final String aliasZid) {
        final ScimUser scimUser = new ScimUser();

        scimUser.setDisplayName("Some Displayname");
        scimUser.setPrimaryEmail("some.email@example.com");

        scimUser.setPhoneNumbers(Collections.singletonList(new ScimUser.PhoneNumber("12345")));

        scimUser.setAliasId(aliasId);
        scimUser.setAliasZid(aliasZid);

        setZoneId(scimUser, zoneId);
        return scimUser;
    }

    @Override
    protected void changeNonAliasProperties(final ScimUser entity) {
        entity.setNickName("some-new-nickname");
    }

    @Override
    protected void setZoneId(final ScimUser entity, final String zoneId) {
        entity.setZoneId(zoneId);
    }

    @Override
    protected void arrangeZoneExists(final String zoneId) {
        if (!zoneId.equals(UAA)) {
            return;
        }
        lenient().when(identityZoneProvisioning.retrieve(zoneId)).thenReturn(null);
    }

    @Override
    protected void arrangeZoneDoesNotExist(final String zoneId) {
        when(identityZoneProvisioning.retrieve(zoneId))
                .thenThrow(new ZoneDoesNotExistsException("Zone does not exist."));
    }

    @Nested
    class NoExistingAlias {
        @Nested
        class AliasFeatureEnabled extends NoExistingAlias_AliasFeatureEnabled {
            private final String customZoneId = UUID.randomUUID().toString();

            @ParameterizedTest
            @EnumSource
            void shouldReturnFalse_IfIdpHasNoAlias_UaaToCustomZone(
                    final ExistingEntityArgument existingEntityArgument
            ) {
                shouldReturnFalse_IfIdpHasNoAlias(existingEntityArgument, UAA, customZoneId);
            }

            @ParameterizedTest
            @EnumSource
            void shouldReturnFalse_IfIdpHasNoAlias_CustomToUaaZone(
                    final ExistingEntityArgument existingEntityArgument
            ) {
                shouldReturnFalse_IfIdpHasNoAlias(existingEntityArgument, customZoneId, UAA);
            }

            private void shouldReturnFalse_IfIdpHasNoAlias(
                    final ExistingEntityArgument existingEntityArgument,
                    final String zone1,
                    final String zone2
            ) {
                arrangeZoneExists(zone1);
                arrangeZoneExists(zone2);

                arrangeCurrentIdz(zone1);

                final ScimUser requestBody = buildEntityWithAliasProps(IdentityZone.getUaaZoneId(), null, zone2);
                requestBody.setZoneId(zone1);
                final String origin = RANDOM_STRING_GENERATOR.generate();
                requestBody.setOrigin(origin);

                final ScimUser existingUser = resolveExistingEntityArgument(existingEntityArgument);
                if (existingUser != null) {
                    existingUser.setZoneId(zone1);
                    existingUser.setOrigin(origin);
                }

                // arrange IdP exists, but without alias
                final IdentityProvider<?> idp = buildIdp(UUID.randomUUID().toString(), origin, zone1, null, null);
                arrangeIdpDoesNotExist(origin, zone2);
                arrangeIdpExists(origin, zone1, idp);

                assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingUser)).isFalse();
            }

            @ParameterizedTest
            @EnumSource
            void shouldReturnFalse_IfIdpOfOriginalUserDoesNotExist_UaaToCustomZone(
                    final ExistingEntityArgument existingEntityArgument
            ) {
                shouldReturnFalse_IfIdpOfOriginalUserDoesNotExist(existingEntityArgument, UAA, customZoneId);
            }

            @ParameterizedTest
            @EnumSource
            void shouldReturnFalse_IfIdpOfOriginalUserDoesNotExist_CustomToUaaZone(
                    final ExistingEntityArgument existingEntityArgument
            ) {
                shouldReturnFalse_IfIdpOfOriginalUserDoesNotExist(existingEntityArgument, customZoneId, UAA);
            }

            private void shouldReturnFalse_IfIdpOfOriginalUserDoesNotExist(
                    final ExistingEntityArgument existingEntityArgument,
                    final String zone1,
                    final String zone2
            ) {
                arrangeZoneExists(zone1);
                arrangeZoneExists(zone2);

                arrangeCurrentIdz(zone1);

                final ScimUser requestBody = buildEntityWithAliasProps(IdentityZone.getUaaZoneId(), null, zone2);
                requestBody.setZoneId(zone1);
                final String origin = RANDOM_STRING_GENERATOR.generate();
                requestBody.setOrigin(origin);

                final ScimUser existingUser = resolveExistingEntityArgument(existingEntityArgument);
                if (existingUser != null) {
                    existingUser.setZoneId(zone1);
                    existingUser.setOrigin(origin);
                }

                // arrange IdP exists for alias user, but not for original user
                final IdentityProvider<?> idp = buildIdp(UUID.randomUUID().toString(), origin, zone1, null, null);
                arrangeIdpDoesNotExist(origin, zone1);
                arrangeIdpExists(origin, zone2, idp);

                assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingUser)).isFalse();
            }

            @ParameterizedTest
            @EnumSource
            void shouldReturnFalse_IfIdpHasAliasToDifferentZoneThanUser(
                    final ExistingEntityArgument existingEntityArgument
            ) {
                arrangeZoneExists(customZoneId);

                // scenario only possible from UAA zone
                arrangeCurrentIdz(UAA);

                final String aliasZidIdp = UUID.randomUUID().toString();
                arrangeZoneExists(aliasZidIdp);

                // should always be true
                assertThat(aliasZidIdp).isNotEqualTo(customZoneId);

                final ScimUser requestBody = buildEntityWithAliasProps(IdentityZone.getUaaZoneId(), null, customZoneId);
                requestBody.setZoneId(UAA);
                final String origin = RANDOM_STRING_GENERATOR.generate();
                requestBody.setOrigin(origin);

                final ScimUser existingUser = resolveExistingEntityArgument(existingEntityArgument);
                if (existingUser != null) {
                    existingUser.setZoneId(UAA);
                    existingUser.setOrigin(origin);
                }

                // arrange IdP exists with alias in different zone than the one referenced in the user
                final String idpId = UUID.randomUUID().toString();
                final String aliasIdpId = UUID.randomUUID().toString();
                final IdentityProvider<?> idp = buildIdp(idpId, origin, UAA, aliasIdpId, aliasZidIdp);
                final IdentityProvider<?> aliasIdp = buildIdp(aliasIdpId, origin, aliasZidIdp, idpId, UAA);
                arrangeIdpExists(origin, UAA, idp);
                arrangeIdpExists(origin, aliasZidIdp, aliasIdp);

                assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingUser)).isFalse();
            }

            @ParameterizedTest
            @EnumSource
            void shouldReturnFalse_IfIdpOfOriginalUserHasEmptyAliasId_UaaToCustomZone(
                    final ExistingEntityArgument existingEntityArgument
            ) {
                shouldReturnFalse_IfIdpOfOriginalUserHasEmptyAliasId(existingEntityArgument, UAA, customZoneId);
            }

            @ParameterizedTest
            @EnumSource
            void shouldReturnFalse_IfIdpOfOriginalUserHasEmptyAliasId_CustomToUaaZone(
                    final ExistingEntityArgument existingEntityArgument
            ) {
                shouldReturnFalse_IfIdpOfOriginalUserHasEmptyAliasId(existingEntityArgument, customZoneId, UAA);
            }

            private void shouldReturnFalse_IfIdpOfOriginalUserHasEmptyAliasId(
                    final ExistingEntityArgument existingEntityArgument,
                    final String zone1,
                    final String zone2
            ) {
                arrangeZoneExists(zone1);
                arrangeZoneExists(zone2);

                arrangeCurrentIdz(zone1);

                final ScimUser requestBody = buildEntityWithAliasProps(IdentityZone.getUaaZoneId(), null, zone2);
                requestBody.setZoneId(zone1);
                final String origin = RANDOM_STRING_GENERATOR.generate();
                requestBody.setOrigin(origin);

                final ScimUser existingUser = resolveExistingEntityArgument(existingEntityArgument);
                if (existingUser != null) {
                    existingUser.setZoneId(zone1);
                    existingUser.setOrigin(origin);
                }

                // arrange IdP exists with alias in same zone as the one referenced in the user, but with empty aliasId
                final String idpId = UUID.randomUUID().toString();
                final String aliasIdpId = UUID.randomUUID().toString();
                final IdentityProvider<?> idp = buildIdp(idpId, origin, zone1, aliasIdpId, zone2);
                idp.setAliasId(""); // arrange IdP of original user has empty alias ID
                final IdentityProvider<?> aliasIdp = buildIdp(aliasIdpId, origin, zone2, idpId, zone1);
                arrangeIdpExists(origin, zone1, idp);
                arrangeIdpExists(origin, zone2, aliasIdp);

                assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingUser)).isFalse();
            }

            @ParameterizedTest
            @EnumSource
            void shouldReturnTrue_IfIdpHasAliasToSameZoneAsUser_UaaToCustomZone(
                    final ExistingEntityArgument existingEntityArgument
            ) {
                shouldReturnTrue_IfIdpHasAliasToSameZoneAsUser(existingEntityArgument, UAA, customZoneId);
            }

            @ParameterizedTest
            @EnumSource
            void shouldReturnTrue_IfIdpHasAliasToSameZoneAsUser_CustomToUaaZone(
                    final ExistingEntityArgument existingEntityArgument
            ) {
                shouldReturnTrue_IfIdpHasAliasToSameZoneAsUser(existingEntityArgument, customZoneId, UAA);
            }

            private void shouldReturnTrue_IfIdpHasAliasToSameZoneAsUser(
                    final ExistingEntityArgument existingEntityArgument,
                    final String zone1,
                    final String zone2
            ) {
                arrangeZoneExists(zone1);
                arrangeZoneExists(zone2);

                arrangeCurrentIdz(zone1);

                final ScimUser requestBody = buildEntityWithAliasProps(IdentityZone.getUaaZoneId(), null, zone2);
                requestBody.setZoneId(zone1);
                final String origin = RANDOM_STRING_GENERATOR.generate();
                requestBody.setOrigin(origin);

                final ScimUser existingUser = resolveExistingEntityArgument(existingEntityArgument);
                if (existingUser != null) {
                    existingUser.setZoneId(zone1);
                    existingUser.setOrigin(origin);
                }

                // arrange IdP exists with alias in same zone as the one referenced in the user
                final String idpId = UUID.randomUUID().toString();
                final String aliasIdpId = UUID.randomUUID().toString();
                final IdentityProvider<?> idp = buildIdp(idpId, origin, zone1, aliasIdpId, zone2);
                final IdentityProvider<?> aliasIdp = buildIdp(aliasIdpId, origin, zone2, idpId, zone1);
                arrangeIdpExists(origin, zone1, idp);
                arrangeIdpExists(origin, zone2, aliasIdp);

                assertThat(aliasHandler.aliasPropertiesAreValid(requestBody, existingUser)).isTrue();
            }

            private void arrangeCurrentIdz(final String zoneId) {
                lenient().when(identityZoneManager.getCurrentIdentityZoneId()).thenReturn(zoneId);
            }

            private static IdentityProvider<?> buildIdp(
                    final String id,
                    final String origin,
                    final String zoneId,
                    final String aliasId,
                    final String aliasZid
            ) {
                final IdentityProvider<?> idp = new IdentityProvider<>();
                idp.setOriginKey(origin);
                idp.setId(id);
                idp.setName(origin);
                idp.setIdentityZoneId(zoneId);
                idp.setAliasId(aliasId);
                idp.setAliasZid(aliasZid);
                return idp;
            }

            private void arrangeIdpDoesNotExist(final String origin, final String zoneId) {
                when(identityProviderProvisioning.retrieveByOrigin(origin, zoneId))
                        .thenThrow(new EmptyResultDataAccessException(1));
            }

            private void arrangeIdpExists(
                    final String origin,
                    final String zoneId,
                    final IdentityProvider<?> idp
            ) {
                lenient().when(identityProviderProvisioning.retrieveByOrigin(origin, zoneId)).thenReturn(idp);
            }
        }

        @Nested
        class AliasFeatureDisabled extends NoExistingAlias_AliasFeatureDisabled {
            // all tests defined in superclass
        }
    }

    @Nested
    class ExistingAlias {
        @Nested
        class AliasFeatureEnabled extends ExistingAlias_AliasFeatureEnabled {
            // all tests defined in superclass
        }

        @Nested
        class AliasFeatureDisabled extends ExistingAlias_AliasFeatureDisabled {
            // all tests defined in superclass
        }
    }
}
