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

  private String secret;

  public UaaClient(String username, String password, Collection<? extends GrantedAuthority> authorities, Map<String, Object> additionalInformation) {
    super(username, password == null ? "" : password, authorities);
    this.additionalInformation = additionalInformation;
    this.secret = password;
  }

  public UaaClient(UserDetails userDetails, String secret) {
    super(userDetails.getUsername(), secret == null ? "" : secret, userDetails.isEnabled(), userDetails.isAccountNonExpired(),
        userDetails.isCredentialsNonExpired(), userDetails.isAccountNonLocked(), userDetails.getAuthorities());
    if (userDetails instanceof UaaClient) {
      this.additionalInformation = ((UaaClient) userDetails).getAdditionalInformation();
    }
    this.secret = secret;
  }

  public boolean isAllowPublic() {
    Object allowPublic = Optional.ofNullable(additionalInformation).map(e -> e.get(ClientConstants.ALLOW_PUBLIC)).orElse(Collections.emptyMap());
    if ((allowPublic instanceof String && Boolean.TRUE.toString().equalsIgnoreCase((String) allowPublic)) || (allowPublic instanceof Boolean && Boolean.TRUE.equals(allowPublic))) {
      return true;
    }
    return false;
  }

  private Map<String, Object> getAdditionalInformation() {
    return this.additionalInformation;
  }

  @Override
  public String getPassword() {
    return this.secret;
  }
}
