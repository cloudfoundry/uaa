package org.cloudfoundry.identity.uaa.client;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;
import java.util.Map;

public class UaaClient extends User {

  Map<String, Object> additionalInformation;

  public UaaClient(String username, String password, Collection<? extends GrantedAuthority> authorities, Map<String, Object> additionalInformation) {
    super(username, password, authorities);
    this.additionalInformation = additionalInformation;
  }

  public Map<String, Object> getAdditionalInformation() {
    return this.additionalInformation;
  }

}
