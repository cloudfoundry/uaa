package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.provider.ClientRegistrationException;
import org.cloudfoundry.identity.uaa.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.ClientDetailsService;

import java.util.HashMap;
import java.util.Map;

public class InMemoryClientDetailsService implements ClientDetailsService {

  private Map<String, UaaClientDetails> clientDetailsStore = new HashMap<String, UaaClientDetails>();

  public UaaClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {
    UaaClientDetails details = clientDetailsStore.get(clientId);
    if (details == null) {
      throw new NoSuchClientException("No client with requested id");
    }
    return details;
  }

  public void setClientDetailsStore(Map<String, ? extends UaaClientDetails> clientDetailsStore) {
    this.clientDetailsStore = new HashMap<String, UaaClientDetails>(clientDetailsStore);
  }

}