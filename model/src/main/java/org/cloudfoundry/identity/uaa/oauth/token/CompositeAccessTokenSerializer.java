package org.cloudfoundry.identity.uaa.oauth.token;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import java.io.IOException;
import java.util.Date;
import java.util.Map;
import java.util.Set;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.util.Assert;

public final class CompositeAccessTokenSerializer extends StdSerializer<CompositeToken> {

  public CompositeAccessTokenSerializer() {
    super(CompositeToken.class);
  }

  @Override
  public void serialize(CompositeToken token, JsonGenerator jgen, SerializerProvider provider)
      throws IOException {

    jgen.writeStartObject();
    jgen.writeStringField(OAuth2AccessToken.ACCESS_TOKEN, token.getValue());
    jgen.writeStringField(OAuth2AccessToken.TOKEN_TYPE, token.getTokenType());
    if (token instanceof CompositeToken && token.getIdTokenValue() != null) {
      jgen.writeStringField(CompositeToken.ID_TOKEN, token.getIdTokenValue());
    }
    OAuth2RefreshToken refreshToken = token.getRefreshToken();
    if (refreshToken != null) {
      jgen.writeStringField(OAuth2AccessToken.REFRESH_TOKEN, refreshToken.getValue());
    }
    Date expiration = token.getExpiration();
    if (expiration != null) {
      long now = System.currentTimeMillis();
      jgen.writeNumberField(OAuth2AccessToken.EXPIRES_IN, (expiration.getTime() - now) / 1000);
    }
    Set<String> scope = token.getScope();
    if (scope != null && !scope.isEmpty()) {
      StringBuffer scopes = new StringBuffer();
      for (String s : scope) {
        Assert.hasLength(s, "Scopes cannot be null or empty. Got " + scope + "");
        scopes.append(s);
        scopes.append(" ");
      }
      jgen.writeStringField(OAuth2AccessToken.SCOPE, scopes.substring(0, scopes.length() - 1));
    }
    Map<String, Object> additionalInformation = token.getAdditionalInformation();
    for (String key : additionalInformation.keySet()) {
      jgen.writeObjectField(key, additionalInformation.get(key));
    }
    jgen.writeEndObject();
  }
}
