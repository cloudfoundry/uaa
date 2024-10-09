package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DelegatingRelyingPartyRegistrationRepositoryTest {

    private static final String REGISTRATION_ID = "test";

    @Mock
    IdentityZone identityZone;

    @Test
    void constructor_WhenRepositoriesAreNull() {
        assertThatThrownBy(() -> {
            new DelegatingRelyingPartyRegistrationRepository((List<RelyingPartyRegistrationRepository>) null);
        }).isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> {
            new DelegatingRelyingPartyRegistrationRepository((RelyingPartyRegistrationRepository[]) null);
        }).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void constructor_whenRepositoriesAreEmpty() {
        assertThatThrownBy(() -> {
            new DelegatingRelyingPartyRegistrationRepository(Collections.emptyList());
        }).isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> {
            new DelegatingRelyingPartyRegistrationRepository(new RelyingPartyRegistrationRepository[]{});
        }).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void findWhenRegistrationNotFound() {
        RelyingPartyRegistrationRepository mockRepository = mock(RelyingPartyRegistrationRepository.class);
        when(mockRepository.findByRegistrationId(anyString())).thenReturn(null);
        DelegatingRelyingPartyRegistrationRepository target = new DelegatingRelyingPartyRegistrationRepository(mockRepository);
        assertThat(target.findByRegistrationId(REGISTRATION_ID)).isNull();
    }

    @Test
    void findWhenRegistrationFound() {
        RelyingPartyRegistration expectedRegistration = mock(RelyingPartyRegistration.class);
        RelyingPartyRegistrationRepository mockRepository1 = mock(RelyingPartyRegistrationRepository.class);

        RelyingPartyRegistrationRepository mockRepository2 = mock(RelyingPartyRegistrationRepository.class);
        when(mockRepository2.findByRegistrationId(REGISTRATION_ID)).thenReturn(expectedRegistration);

        DelegatingRelyingPartyRegistrationRepository target = new DelegatingRelyingPartyRegistrationRepository(mockRepository1, mockRepository2);
        assertThat(target.findByRegistrationId(REGISTRATION_ID)).isEqualTo(expectedRegistration);

        verify(mockRepository1).findByRegistrationId(REGISTRATION_ID);
        verify(mockRepository2).findByRegistrationId(REGISTRATION_ID);
    }

    @Test
    void findWhenZonedRegistrationFound() {
        when(identityZone.isUaa()).thenReturn(false);

        RelyingPartyRegistration expectedRegistration = mock(RelyingPartyRegistration.class);
        RelyingPartyRegistrationRepository mockRepository1 = mock(RelyingPartyRegistrationRepository.class);

        RelyingPartyRegistrationRepository mockRepository2 = mock(DefaultRelyingPartyRegistrationRepository.class);
        when(mockRepository2.findByRegistrationId(REGISTRATION_ID)).thenReturn(expectedRegistration);

        DelegatingRelyingPartyRegistrationRepository target = spy(new DelegatingRelyingPartyRegistrationRepository(mockRepository1, mockRepository2));
        when(target.retrieveZone()).thenReturn(identityZone);
        assertThat(target.findByRegistrationId(REGISTRATION_ID)).isEqualTo(expectedRegistration);

        // is not ZoneAware, so it should not call findByRegistrationId
        verify(mockRepository1, never()).findByRegistrationId(REGISTRATION_ID);
    }
}
