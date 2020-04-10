package org.cloudfoundry.identity.uaa.zone;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TokenFormat.JWT;

import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonSetter;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collector;
import java.util.stream.Collectors;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.springframework.util.StringUtils;

@JsonIgnoreProperties(ignoreUnknown = true)
public class TokenPolicy {

  private static final Collector<
      ? super Map.Entry<String, String>, ?, ? extends Map<String, KeyInformation>>
      outputCollector =
      Collectors.toMap(
          Map.Entry::getKey,
          e -> {
            KeyInformation keyInformation = new KeyInformation();
            keyInformation.setSigningKey(e.getValue());
            return keyInformation;
          });
  private static final Collector<
      ? super Map.Entry<String, KeyInformation>, ?, ? extends Map<String, String>>
      inputCollector = Collectors.toMap(Map.Entry::getKey, e -> e.getValue().getSigningKey());

  private int accessTokenValidity;
  private int refreshTokenValidity;
  private boolean jwtRevocable = false;
  private boolean refreshTokenUnique = false;
  private String refreshTokenFormat = JWT.getStringValue();
  private Map<String, String> keys;
  private String activeKeyId;

  public TokenPolicy() {
    accessTokenValidity = refreshTokenValidity = -1;
  }

  public TokenPolicy(int accessTokenValidity, int refreshTokenValidity) {
    this.accessTokenValidity = accessTokenValidity;
    this.refreshTokenValidity = refreshTokenValidity;
  }

  public TokenPolicy(
      int accessTokenValidity,
      int refreshTokenValidity,
      Map<String, ? extends Map<String, String>> signingKeysMap) {
    this(accessTokenValidity, refreshTokenValidity);
    setKeysLegacy(
        signingKeysMap.entrySet().stream()
            .collect(
                Collectors.toMap(
                    Map.Entry::getKey,
                    e -> {
                      KeyInformation keyInformation = new KeyInformation();
                      keyInformation.setSigningKey(e.getValue().get("signingKey"));
                      return keyInformation;
                    })));
  }

  @JsonGetter("keys")
  @JsonInclude(JsonInclude.Include.NON_NULL)
  private Map<String, KeyInformation> getKeysLegacy() {
    Map<String, String> keys = getKeys();
    return (keys == null || keys.isEmpty())
        ? null
        : keys.entrySet().stream().collect(outputCollector);
  }

  @JsonSetter("keys")
  private void setKeysLegacy(Map<String, KeyInformation> keys) {
    setKeys(keys == null ? null : keys.entrySet().stream().collect(inputCollector));
  }

  public int getAccessTokenValidity() {
    return accessTokenValidity;
  }

  public void setAccessTokenValidity(int accessTokenValidity) {
    this.accessTokenValidity = accessTokenValidity;
  }

  public int getRefreshTokenValidity() {
    return refreshTokenValidity;
  }

  public void setRefreshTokenValidity(int refreshTokenValidity) {
    this.refreshTokenValidity = refreshTokenValidity;
  }

  @JsonIgnore
  public Map<String, String> getKeys() {
    return this.keys == null ? Collections.EMPTY_MAP : new HashMap<>(this.keys);
  }

  @JsonIgnore
  public void setKeys(Map<String, String> keys) {
    if (keys != null) {
      keys.forEach(
          (key, value) -> {
            if (!StringUtils.hasText(value) || !StringUtils.hasText(key)) {
              throw new IllegalArgumentException(
                  "KeyId and Signing key should not be null or empty");
            }
          });
    }
    this.keys = keys == null ? null : new HashMap<>(keys);
  }

  public boolean isRefreshTokenUnique() {
    return refreshTokenUnique;
  }

  public void setRefreshTokenUnique(boolean refreshTokenUnique) {
    this.refreshTokenUnique = refreshTokenUnique;
  }

  public String getRefreshTokenFormat() {
    return refreshTokenFormat;
  }

  public void setRefreshTokenFormat(String refreshTokenFormat) {
    if (TokenConstants.TokenFormat.fromStringValue(refreshTokenFormat) == null) {
      List<String> validFormats = TokenConstants.TokenFormat.getStringValues();
      String message =
          String.format(
              "Invalid refresh token format %s. Acceptable values are: %s",
              refreshTokenFormat, validFormats.toString());
      throw new IllegalArgumentException(message);
    }
    this.refreshTokenFormat = refreshTokenFormat.toLowerCase();
  }

  public String getActiveKeyId() {
    return activeKeyId;
  }

  public void setActiveKeyId(String activeKeyId) {
    this.activeKeyId = activeKeyId;
  }

  public boolean isJwtRevocable() {
    return jwtRevocable;
  }

  public void setJwtRevocable(boolean jwtRevocable) {
    this.jwtRevocable = jwtRevocable;
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  private static class KeyInformation {

    private String signingKey;

    public String getSigningKey() {
      return signingKey;
    }

    public void setSigningKey(String signingKey) {
      this.signingKey = signingKey;
    }
  }
}
