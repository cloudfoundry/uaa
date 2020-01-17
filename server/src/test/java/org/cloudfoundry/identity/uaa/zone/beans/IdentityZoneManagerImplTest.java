package org.cloudfoundry.identity.uaa.zone.beans;

import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import java.util.UUID;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(PollutionPreventionExtension.class)
class IdentityZoneManagerImplTest {

    private IdentityZoneManager identityZoneManager;
    private IdentityZone mockIdentityZone;

    @BeforeEach
    void setUp() {
        identityZoneManager = new IdentityZoneManagerImpl();
        mockIdentityZone = mock(IdentityZone.class);
        identityZoneManager.setCurrentIdentityZone(mockIdentityZone);
    }

    @Test
    void getCurrentIdentityZone() {
        assertThat(identityZoneManager.getCurrentIdentityZone(), is(mockIdentityZone));
    }

    @Test
    void getCurrentIdentityZoneId() {
        String zoneId = UUID.randomUUID().toString();
        when(mockIdentityZone.getId()).thenReturn(zoneId);

        assertThat(identityZoneManager.getCurrentIdentityZoneId(), is(zoneId));
    }

    @Nested
    class WhenZoneIsUaa {
        @BeforeEach
        void setUp() {
            when(mockIdentityZone.isUaa()).thenReturn(true);
        }

        @Test
        void isCurrentZoneUaa() {
            assertThat(identityZoneManager.isCurrentZoneUaa(), is(true));
        }
    }

    @Nested
    class WhenZoneIsNotUaa {
        @BeforeEach
        void setUp() {
            when(mockIdentityZone.isUaa()).thenReturn(false);
        }

        @Test
        void isCurrentZoneUaa() {
            assertThat(identityZoneManager.isCurrentZoneUaa(), is(false));
        }
    }
}