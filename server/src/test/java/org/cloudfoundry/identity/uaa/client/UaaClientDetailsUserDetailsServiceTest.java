package org.cloudfoundry.identity.uaa.client;

import org.assertj.core.api.InstanceOfAssertFactories;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;
import org.cloudfoundry.identity.uaa.oauth.provider.token.UserAuthenticationConverter;
import org.cloudfoundry.identity.uaa.provider.ClientRegistrationException;
import org.cloudfoundry.identity.uaa.provider.NoSuchClientException;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class UaaClientDetailsUserDetailsServiceTest {
    @SuppressWarnings("unchecked")
    @Test
    void shouldThrowUsernameNotFoundExceptionWhenNoSuchClient() {
        Map<String, Object> map = new HashMap<>();
        map.put(UserAuthenticationConverter.USERNAME, "test_user");

        ClientDetailsService clientDetailsService = Mockito.mock(ClientDetailsService.class);
        Mockito.when(clientDetailsService.loadClientByClientId("test_user")).thenThrow(NoSuchClientException.class);
        UaaClientDetailsUserDetailsService testee = new UaaClientDetailsUserDetailsService(clientDetailsService);
        assertThatThrownBy(() -> testee.loadUserByUsername("test_user")).asInstanceOf(InstanceOfAssertFactories.throwable(UsernameNotFoundException.class));
    }

    @SuppressWarnings("unchecked")
    @Test
    void shouldConductOriginalException() {
        Map<String, Object> map = new HashMap<>();
        map.put(UserAuthenticationConverter.USERNAME, "test_user");

        ClientDetailsService clientDetailsService = Mockito.mock(ClientDetailsService.class);
        Mockito.when(clientDetailsService.loadClientByClientId("test_user")).thenThrow(ClientRegistrationException.class);
        UaaClientDetailsUserDetailsService testee = new UaaClientDetailsUserDetailsService(clientDetailsService);
        assertThatThrownBy(() -> testee.loadUserByUsername("test_user")).asInstanceOf(InstanceOfAssertFactories.throwable(ClientRegistrationException.class));
    }
}
