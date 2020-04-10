package org.cloudfoundry.identity.uaa.oauth.token;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

@JsonSerialize(using = CompositeAccessTokenSerializer.class)
@JsonDeserialize(using = CompositeAccessTokenDeserializer.class)
public class CompositeToken extends DefaultOAuth2AccessToken {

  public static String ID_TOKEN = "id_token";
  private String idTokenValue;

  public CompositeToken(String accessTokenValue) {
    super(accessTokenValue);
  }

  public CompositeToken(OAuth2AccessToken accessToken) {
    super(accessToken);
  }

  public String getIdTokenValue() {
    return idTokenValue;
  }

  public void setIdTokenValue(String idTokenValue) {
    this.idTokenValue = idTokenValue;
  }
}
