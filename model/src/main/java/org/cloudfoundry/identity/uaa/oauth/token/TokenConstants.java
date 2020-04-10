package org.cloudfoundry.identity.uaa.oauth.token;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class TokenConstants {

  public static final String REQUEST_TOKEN_FORMAT = "token_format";
  public static final String REQUEST_AUTHORITIES = "authorities";
  public static final String USER_TOKEN_REQUESTING_CLIENT_ID = "requesting_client_id";
  public static final String REFRESH_TOKEN_SUFFIX = "-r";
  public static final String GRANT_TYPE_SAML2_BEARER =
      "urn:ietf:params:oauth:grant-type:saml2-bearer";
  public static final String GRANT_TYPE_JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer";
  public static final String GRANT_TYPE_USER_TOKEN = "user_token";
  public static final String GRANT_TYPE_REFRESH_TOKEN = "refresh_token";
  public static final String GRANT_TYPE_PASSWORD = "password";
  public static final String GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials";
  public static final String GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code";
  public static final String GRANT_TYPE_IMPLICIT = "implicit";
  public static final String ID_TOKEN_HINT_PROMPT = "prompt";
  public static final String ID_TOKEN_HINT_PROMPT_NONE = "none";

  public enum TokenFormat {
    OPAQUE("opaque"),
    JWT("jwt");

    private String stringValue;

    TokenFormat(String string) {
      this.stringValue = string;
    }

    public static TokenFormat fromStringValue(String stringValue) {
      for (TokenFormat tokenFormat : TokenFormat.values()) {
        if (tokenFormat.stringValue.equalsIgnoreCase(stringValue)) {
          return tokenFormat;
        }
      }
      return null;
    }

    public static List<String> getStringValues() {
      return Arrays.stream(TokenFormat.values())
          .map(TokenFormat::getStringValue)
          .collect(Collectors.toList());
    }

    public String getStringValue() {
      return this.stringValue;
    }
  }
}
