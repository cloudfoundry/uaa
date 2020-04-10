package org.cloudfoundry.identity.uaa.oauth.refresh;

import java.util.Date;
import org.springframework.security.oauth2.common.DefaultExpiringOAuth2RefreshToken;

public class CompositeExpiringOAuth2RefreshToken extends DefaultExpiringOAuth2RefreshToken {

  private String jti;

  /** */
  public CompositeExpiringOAuth2RefreshToken(String value, Date expiration, String jti) {
    super(value, expiration);
    this.jti = jti;
  }

  public String getJti() {
    return jti;
  }

  public void setJti(String jti) {
    this.jti = jti;
  }
}
