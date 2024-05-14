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

public class ProxyingRelyingPartyRegistrationRepositoryTest {

    @Test
    public void constructor_WhenRepositoriesAreNull() {
        assertThrows(IllegalArgumentException.class, () -> {
            new ProxyingRelyingPartyRegistrationRepository((List<RelyingPartyRegistrationRepository>) null);
        });

        assertThrows(IllegalArgumentException.class, () -> {
            new ProxyingRelyingPartyRegistrationRepository((RelyingPartyRegistrationRepository[]) null);
        });
    }

    @Test
    public void constructor_whenRepositoriesAreEmpty() {
        assertThrows(IllegalArgumentException.class, () -> {
            new ProxyingRelyingPartyRegistrationRepository(Collections.emptyList());
        });

        assertThrows(IllegalArgumentException.class, () -> {
            new ProxyingRelyingPartyRegistrationRepository(new RelyingPartyRegistrationRepository[]{});
        });
    }

    @Test
    public void findWhenRegistrationNotFound() {
        RelyingPartyRegistrationRepository mockRepository = mock(RelyingPartyRegistrationRepository.class);
        when(mockRepository.findByRegistrationId(anyString())).thenReturn(null);
        ProxyingRelyingPartyRegistrationRepository target = new ProxyingRelyingPartyRegistrationRepository(mockRepository);
        assertNull(target.findByRegistrationId("test"));
    }

    @Test
    public void findWhenRegistrationFound() {
        RelyingPartyRegistration expectedRegistration = mock(RelyingPartyRegistration.class);
        RelyingPartyRegistrationRepository mockRepository1 = mock(RelyingPartyRegistrationRepository.class);
        when(mockRepository1.findByRegistrationId(eq("test"))).thenReturn(null);

        RelyingPartyRegistrationRepository mockRepository2 = mock(RelyingPartyRegistrationRepository.class);
        when(mockRepository2.findByRegistrationId(eq("test"))).thenReturn(expectedRegistration);

        ProxyingRelyingPartyRegistrationRepository target = new ProxyingRelyingPartyRegistrationRepository(mockRepository1, mockRepository2);
        assertEquals(expectedRegistration, target.findByRegistrationId("test"));
    }
}