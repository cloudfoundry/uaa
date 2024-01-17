package org.cloudfoundry.identity.uaa.provider;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.cloudfoundry.identity.uaa.provider.IdpAliasFailedException.Reason.ALIAS_ZONE_DOES_NOT_EXIST;
import static org.cloudfoundry.identity.uaa.provider.IdpAliasFailedException.Reason.ORIGIN_KEY_ALREADY_USED_IN_ALIAS_ZONE;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.UUID;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class IdpAliasFailedExceptionTest {
    private static final String IDP_ID = UUID.randomUUID().toString();
    private static final String IDZ_ID = UUID.randomUUID().toString();
    private static final String ALIAS_ID = UUID.randomUUID().toString();
    private static final String ALIAS_ZID = UAA;

    private static IdentityProvider<?> mockIdentityProvider;

    @BeforeAll
    static void beforeAll() {
        mockIdentityProvider = mock(IdentityProvider.class);
        when(mockIdentityProvider.getId()).thenReturn(IDP_ID);
        when(mockIdentityProvider.getIdentityZoneId()).thenReturn(IDZ_ID);
        when(mockIdentityProvider.getAliasId()).thenReturn(ALIAS_ID);
        when(mockIdentityProvider.getAliasZid()).thenReturn(ALIAS_ZID);
    }

    @Test
    void testOriginKeyAlreadyUserInAliasZone() {
        final IdpAliasFailedException exception = new IdpAliasFailedException(
                mockIdentityProvider,
                ORIGIN_KEY_ALREADY_USED_IN_ALIAS_ZONE,
                null
        );

        assertThat(exception.getMessage()).isEqualTo(
                "IdentityProvider[id='%s',zid='%s',aliasId='%s',aliasZid='%s'] - An IdP with this origin already exists in the alias zone.".formatted(
                        mockIdentityProvider.getId(),
                        mockIdentityProvider.getIdentityZoneId(),
                        mockIdentityProvider.getAliasId(),
                        mockIdentityProvider.getAliasZid()
                )
        );
    }

    @Test
    void testAliasZoneDoesNotExist() {
        final IdpAliasFailedException exception = new IdpAliasFailedException(
                mockIdentityProvider,
                ALIAS_ZONE_DOES_NOT_EXIST,
                null
        );

        assertThat(exception.getMessage()).isEqualTo(
                "IdentityProvider[id='%s',zid='%s',aliasId='%s',aliasZid='%s'] - The referenced alias zone does not exist.".formatted(
                        mockIdentityProvider.getId(),
                        mockIdentityProvider.getIdentityZoneId(),
                        mockIdentityProvider.getAliasId(),
                        mockIdentityProvider.getAliasZid()
                )
        );
    }
}