package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;
import org.cloudfoundry.identity.uaa.oauth.provider.token.UserAuthenticationConverter;
import org.cloudfoundry.identity.uaa.provider.ClientRegistrationException;
import org.cloudfoundry.identity.uaa.provider.NoSuchClientException;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.HashMap;
import java.util.Map;

public class UaaClientDetailsUserDetailsServiceTest {

  @SuppressWarnings("unchecked")
  @Test(expected = UsernameNotFoundException.class)
  public void shouldThrowUsernameNotFoundExceptionWhenNoSuchClient() throws Exception {

    Map<String, Object> map = new HashMap<String, Object>();
    map.put(UserAuthenticationConverter.USERNAME, "test_user");

    ClientDetailsService clientDetailsService = Mockito.mock(ClientDetailsService.class);
    Mockito.when(clientDetailsService.loadClientByClientId("test_user")).thenThrow(NoSuchClientException.class);
    UaaClientDetailsUserDetailsService testee = new UaaClientDetailsUserDetailsService(clientDetailsService);

    testee.loadUserByUsername("test_user");
  }

  @SuppressWarnings("unchecked")
  @Test(expected = ClientRegistrationException.class)
  public void shouldConductOriginalException() throws Exception {

    Map<String, Object> map = new HashMap<String, Object>();
    map.put(UserAuthenticationConverter.USERNAME, "test_user");

    ClientDetailsService clientDetailsService = Mockito.mock(ClientDetailsService.class);
    Mockito.when(clientDetailsService.loadClientByClientId("test_user")).thenThrow(ClientRegistrationException.class);
    UaaClientDetailsUserDetailsService testee = new UaaClientDetailsUserDetailsService(clientDetailsService);

    testee.loadUserByUsername("test_user");
  }

}