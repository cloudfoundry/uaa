package org.cloudfoundry.identity.uaa.provider.saml;

import org.junit.jupiter.api.Test;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class DelegatingRelyingPartyRegistrationRepositoryTest {

    @Test
    void constructor_WhenRepositoriesAreNull() {
        assertThrows(IllegalArgumentException.class, () -> {
            new DelegatingRelyingPartyRegistrationRepository((List<RelyingPartyRegistrationRepository>) null);
        });

        assertThrows(IllegalArgumentException.class, () -> {
            new DelegatingRelyingPartyRegistrationRepository((RelyingPartyRegistrationRepository[]) null);
        });
    }

    @Test
    void constructor_whenRepositoriesAreEmpty() {
        assertThrows(IllegalArgumentException.class, () -> {
            new DelegatingRelyingPartyRegistrationRepository(Collections.emptyList());
        });

        assertThrows(IllegalArgumentException.class, () -> {
            new DelegatingRelyingPartyRegistrationRepository(new RelyingPartyRegistrationRepository[]{});
        });
    }

    @Test
    void findWhenRegistrationNotFound() {
        RelyingPartyRegistrationRepository mockRepository = mock(RelyingPartyRegistrationRepository.class);
        when(mockRepository.findByRegistrationId(anyString())).thenReturn(null);
        DelegatingRelyingPartyRegistrationRepository target = new DelegatingRelyingPartyRegistrationRepository(mockRepository);
        assertNull(target.findByRegistrationId("test"));
    }

    @Test
    void findWhenRegistrationFound() {
        RelyingPartyRegistration expectedRegistration = mock(RelyingPartyRegistration.class);
        RelyingPartyRegistrationRepository mockRepository1 = mock(RelyingPartyRegistrationRepository.class);
        when(mockRepository1.findByRegistrationId(eq("test"))).thenReturn(null);

        RelyingPartyRegistrationRepository mockRepository2 = mock(RelyingPartyRegistrationRepository.class);
        when(mockRepository2.findByRegistrationId(eq("test"))).thenReturn(expectedRegistration);

        DelegatingRelyingPartyRegistrationRepository target = new DelegatingRelyingPartyRegistrationRepository(mockRepository1, mockRepository2);
        assertEquals(expectedRegistration, target.findByRegistrationId("test"));
    }
}