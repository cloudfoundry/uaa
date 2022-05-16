package org.cloudfoundry.identity.uaa.client;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.NoSuchClientException;

public class UaaClientDetailsUserDetailsService implements UserDetailsService {

  private final ClientDetailsService clientDetailsService;
  private String emptyPassword = "";

  public UaaClientDetailsUserDetailsService(final ClientDetailsService clientDetailsService) {
    this.clientDetailsService = clientDetailsService;
  }

  /**
   * @param passwordEncoder the password encoder to set
   */
  public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
    this.emptyPassword = passwordEncoder.encode("");
  }

  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    ClientDetails clientDetails;
    try {
      clientDetails = clientDetailsService.loadClientByClientId(username);
    } catch (NoSuchClientException e) {
      throw new UsernameNotFoundException(e.getMessage(), e);
    }
    String clientSecret = clientDetails.getClientSecret();
    if (clientSecret== null || clientSecret.trim().length()==0) {
      clientSecret = emptyPassword;
    }
    return new UaaClient(username, clientSecret, clientDetails.getAuthorities(), clientDetails.getAdditionalInformation());
  }

}
