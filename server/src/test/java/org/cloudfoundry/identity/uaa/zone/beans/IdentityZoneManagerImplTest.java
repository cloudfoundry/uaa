package org.cloudfoundry.identity.uaa.zone.beans;

import org.cloudfoundry.identity.uaa.security.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import java.util.UUID;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(PollutionPreventionExtension.class)
class IdentityZoneManagerImplTest {
    @Test
    void getCurrentIdentityZoneId() {
        String zoneId = UUID.randomUUID().toString();
        IdentityZone mockIdentityZone = mock(IdentityZone.class);
        when(mockIdentityZone.getId()).thenReturn(zoneId);
        IdentityZoneHolder.set(mockIdentityZone);

        IdentityZoneManager identityZoneManager = new IdentityZoneManagerImpl();

        assertThat(identityZoneManager.getCurrentIdentityZoneId(), is(zoneId));
    }
}