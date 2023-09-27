package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;

public class UaaClient extends User {

  private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
  private transient Map<String, Object> additionalInformation;

  private final String secret;
  private final String clientJwtConfig;

  public UaaClient(String username, String password, Collection<? extends GrantedAuthority> authorities, Map<String, Object> additionalInformation,
      String clientJwtConfig) {
    super(username, password == null ? "" : password, authorities);
    this.additionalInformation = additionalInformation;
    this.secret = password;
    this.clientJwtConfig = clientJwtConfig;
  }

  public UaaClient(UserDetails userDetails, String secret) {
    super(userDetails.getUsername(), secret == null ? "" : secret, userDetails.isEnabled(), userDetails.isAccountNonExpired(),
        userDetails.isCredentialsNonExpired(), userDetails.isAccountNonLocked(), userDetails.getAuthorities());
    if (userDetails instanceof UaaClient) {
      this.additionalInformation = ((UaaClient) userDetails).getAdditionalInformation();
      this.clientJwtConfig = ((UaaClient) userDetails).clientJwtConfig;
    } else {
      this.clientJwtConfig = null;
    }
    this.secret = secret;
  }

  public boolean isAllowPublic() {
    Object allowPublic = Optional.ofNullable(additionalInformation).map(e -> e.get(ClientConstants.ALLOW_PUBLIC)).orElse(Collections.emptyMap());
    if ((allowPublic instanceof String && Boolean.TRUE.toString().equalsIgnoreCase((String) allowPublic)) || (allowPublic instanceof Boolean && Boolean.TRUE.equals(allowPublic))) {
      return true;
    } else {
      return false;
    }
  }

  private Map<String, Object> getAdditionalInformation() {
    return this.additionalInformation;
  }

  public ClientJwtConfiguration getClientJwtConfiguration() {
    UaaClientDetails uaaClientDetails = new UaaClientDetails();
    uaaClientDetails.setClientJwtConfig(clientJwtConfig);
    return Optional.ofNullable(ClientJwtConfiguration.readValue(uaaClientDetails)).orElse(new ClientJwtConfiguration());
  }

  /**
   * Allow to return a null password. Super class does not allow to omit a password, therefore use own method
   *
   * @return The password of the client, can be null if no secret is set
   */
  @Override
  public String getPassword() {
    return this.secret;
  }
}
