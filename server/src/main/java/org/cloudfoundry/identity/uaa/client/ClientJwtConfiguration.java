package org.cloudfoundry.identity.uaa.client;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKeyHelper;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKeySet;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;

import java.net.URI;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.cloudfoundry.identity.uaa.oauth.client.ClientConstants.PRIVATE_KEY_CONFIG;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class ClientJwtConfiguration implements Cloneable{

  @JsonIgnore
  private static final int MAX_KEY_SIZE = 10;

  @JsonProperty("jwks_uri")
  private String privateKeyJwtUrl;

  @JsonProperty("jwks")
  private JsonWebKeySet<JsonWebKey> privateKeyJwt;

  public ClientJwtConfiguration() {
  }

  public ClientJwtConfiguration(final String privateKeyJwtUrl, final JsonWebKeySet<JsonWebKey> webKeySet) {
    this.privateKeyJwtUrl = privateKeyJwtUrl;
    privateKeyJwt = webKeySet;
    if (privateKeyJwt != null) {
      validateJwkSet();
    }
  }

  public String getPrivateKeyJwtUrl() {
    return this.privateKeyJwtUrl;
  }

  public void setPrivateKeyJwtUrl(final String privateKeyJwtUrl) {
    this.privateKeyJwtUrl = privateKeyJwtUrl;
  }

  public JsonWebKeySet<JsonWebKey> getPrivateKeyJwt() {
    return this.privateKeyJwt;
  }

  public void setPrivateKeyJwt(final JsonWebKeySet<JsonWebKey> privateKeyJwt) {
    this.privateKeyJwt = privateKeyJwt;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;

    if (o instanceof ClientJwtConfiguration) {
      ClientJwtConfiguration that = (ClientJwtConfiguration) o;
      if (!Objects.equals(privateKeyJwtUrl, that.privateKeyJwtUrl)) return false;
      if (privateKeyJwt != null && that.privateKeyJwt != null) {
        return privateKeyJwt.getKeys().equals(that.privateKeyJwt.getKeys());
      } else {
        return Objects.equals(privateKeyJwt, that.privateKeyJwt);
      }
    }
    return false;
  }

  @Override
  public int hashCode() {
    int result = super.hashCode();

    result = 31 * result + (privateKeyJwtUrl != null ? privateKeyJwtUrl.hashCode() : 0);
    result = 31 * result + (privateKeyJwt != null ? privateKeyJwt.hashCode() : 0);
    return result;
  }

  @Override
  public Object clone() throws CloneNotSupportedException {
    return super.clone();
  }

  @JsonIgnore
  public String getCleanString() {
    try {
      if (UaaUrlUtils.isUrl(this.privateKeyJwtUrl)) {
        return this.privateKeyJwtUrl;
      } else if (this.privateKeyJwt != null && !ObjectUtils.isEmpty(this.privateKeyJwt.getKeySetMap())) {
        return JWKSet.parse(this.privateKeyJwt.getKeySetMap()).toString(true);
      }
    } catch (IllegalStateException | JsonUtils.JsonUtilException | ParseException e) {
      throw new InvalidClientDetailsException("Client jwt configuration configuration fails ", e);
    }
    return null;
  }

  @JsonIgnore
  public static ClientJwtConfiguration parse(String privateKeyConfig) {
    if (UaaUrlUtils.isUrl(privateKeyConfig)) {
      return parse(privateKeyConfig, null);
    } else {
      return parse(null, privateKeyConfig);
    }
  }

  @JsonIgnore
  public static ClientJwtConfiguration parse(String privateKeyUrl, String privateKeyJwt) {
    ClientJwtConfiguration clientJwtConfiguration = null;
    if (privateKeyUrl != null) {
      clientJwtConfiguration = new ClientJwtConfiguration(privateKeyUrl, null);
      clientJwtConfiguration.validateJwksUri();
    } else if (privateKeyJwt != null && privateKeyJwt.contains("{") && privateKeyJwt.contains("}")) {
      HashMap<String, Object> jsonMap = JsonUtils.readValue(privateKeyJwt, HashMap.class);
      String cleanJwtString;
      try {
        if (jsonMap.containsKey("keys")) {
          cleanJwtString = JWKSet.parse(jsonMap).toString(true);
        } else {
          cleanJwtString = JWK.parse(jsonMap).toPublicJWK().toString();
        }
        clientJwtConfiguration = new ClientJwtConfiguration(null, JsonWebKeyHelper.deserialize(cleanJwtString));
        clientJwtConfiguration.validateJwkSet();
      } catch (ParseException e) {
        throw new InvalidClientDetailsException("Client jwt configuration cannot be parsed", e);
      }
    }
    return clientJwtConfiguration;
  }

  private boolean validateJwkSet() {
    List<JsonWebKey> keyList = privateKeyJwt.getKeys();
    if (keyList.isEmpty() || keyList.size() > MAX_KEY_SIZE) {
      throw new InvalidClientDetailsException("Invalid private_key_jwt: jwk set is empty of exceeds to maximum of keys. max: + " + MAX_KEY_SIZE);
    }
    Set<String> keyId = new HashSet<>();
    keyList.forEach(key -> {
      if (!StringUtils.hasText(key.getKid())) {
        throw new InvalidClientDetailsException("Invalid private_key_jwt: kid is required attribute");
      }
      keyId.add(key.getKid());
    });
    if (keyId.size() != keyList.size()) {
      throw new InvalidClientDetailsException("Invalid private_key_jwt: duplicate kid in JWKSet not allowed");
    }
    return true;
  }

  private boolean validateJwksUri() {
    URI jwksUri;
    try {
      jwksUri = URI.create(privateKeyJwtUrl);
    } catch (IllegalArgumentException e) {
      throw new InvalidClientDetailsException("Invalid private_key_jwt: jwks_uri must be URI complaint", e);
    }
    if (!jwksUri.isAbsolute()) {
      throw new InvalidClientDetailsException("Invalid private_key_jwt: jwks_uri must be an absolute URL");
    }
    if (!"https".equals(jwksUri.getScheme()) && !"http".equals(jwksUri.getScheme())) {
      throw new InvalidClientDetailsException("Invalid private_key_jwt: jwks_uri must be either using https or http");
    }
    if ("http".equals(jwksUri.getScheme()) && !jwksUri.getHost().endsWith("localhost")) {
      throw new InvalidClientDetailsException("Invalid private_key_jwt: jwks_uri with http is not on localhost");
    }
    return true;
  }

  /**
   * Creator from ClientDetails. Should abstract the persistence.
   * Use currently the additional information entry
   *
   * @param clientDetails
   * @return
   */
  @JsonIgnore
  public static ClientJwtConfiguration readValue(ClientDetails clientDetails) {
    if (clientDetails == null ||
        clientDetails.getAdditionalInformation() == null ||
        !(clientDetails.getAdditionalInformation().get(PRIVATE_KEY_CONFIG) instanceof String)) {
      return null;
    }
    return JsonUtils.readValue((String) clientDetails.getAdditionalInformation().get(PRIVATE_KEY_CONFIG), ClientJwtConfiguration.class);
  }

  /**
   * Creator from ClientDetails. Should abstract the persistence.
   * Use currently the additional information entry
   *
   * @param clientDetails
   * @return
   */
  @JsonIgnore
  public void writeValue(ClientDetails clientDetails) {
    if (clientDetails instanceof BaseClientDetails) {
      BaseClientDetails baseClientDetails = (BaseClientDetails) clientDetails;
      HashMap<String, Object> additionalInformation = Optional.ofNullable(baseClientDetails.getAdditionalInformation()).map(HashMap::new).orElse(new HashMap<>());
      additionalInformation.put(PRIVATE_KEY_CONFIG, JsonUtils.writeValueAsString(this));
      baseClientDetails.setAdditionalInformation(additionalInformation);
    }
  }

  /**
   * Cleanup configuration in ClientDetails. Should abstract the persistence.
   * Use currently the additional information entry
   *
   * @param clientDetails
   * @return
   */
  @JsonIgnore
  public static void resetConfiguration(ClientDetails clientDetails) {
    if (clientDetails instanceof BaseClientDetails) {
      BaseClientDetails baseClientDetails = (BaseClientDetails) clientDetails;
      HashMap<String, Object> additionalInformation = Optional.ofNullable(baseClientDetails.getAdditionalInformation()).map(HashMap::new).orElse(new HashMap<>());
      additionalInformation.remove(PRIVATE_KEY_CONFIG);
      baseClientDetails.setAdditionalInformation(additionalInformation);
    }
  }

  @JsonIgnore
  public static ClientJwtConfiguration merge(ClientJwtConfiguration existingConfig, ClientJwtConfiguration newConfig, boolean overwrite) {
    if (existingConfig == null) {
      return newConfig;
    }
    if (newConfig == null) {
      return existingConfig;
    }
    ClientJwtConfiguration result = null;
    if (newConfig.privateKeyJwtUrl != null) {
      if (overwrite) {
        result = new ClientJwtConfiguration(newConfig.privateKeyJwtUrl, null);
      } else {
        result = existingConfig;
      }
    }
    if (newConfig.privateKeyJwt != null) {
      if (existingConfig.privateKeyJwt == null) {
        if (overwrite) {
          result = new ClientJwtConfiguration(null, newConfig.privateKeyJwt);
        } else {
          result = existingConfig;
        }
      } else {
        JsonWebKeySet<JsonWebKey> existingKeySet = existingConfig.privateKeyJwt;
        List<JsonWebKey> existingKeys = new ArrayList<>(existingKeySet.getKeys());
        List<JsonWebKey> newKeys = new ArrayList<>();
        newConfig.getPrivateKeyJwt().getKeys().forEach(key -> {
          if (existingKeys.contains(key)) {
            if (overwrite) {
              existingKeys.remove(key);
              newKeys.add(key);
            }
          } else {
            newKeys.add(key);
          }
        });
        existingKeys.addAll(newKeys);
        result = new ClientJwtConfiguration(null, new JsonWebKeySet<>(existingKeys));
      }
    }
    return result;
  }

  @JsonIgnore
  public static ClientJwtConfiguration delete(ClientJwtConfiguration existingConfig, ClientJwtConfiguration tobeDeleted) {
    if (existingConfig == null) {
      return null;
    }
    if (tobeDeleted == null) {
      return existingConfig;
    }
    ClientJwtConfiguration result = null;
    if (existingConfig.privateKeyJwt != null && tobeDeleted.privateKeyJwtUrl != null) {
      JsonWebKeySet<JsonWebKey> existingKeySet = existingConfig.privateKeyJwt;
      List<JsonWebKey> keys = existingKeySet.getKeys().stream().filter(k -> !tobeDeleted.privateKeyJwtUrl.equals(k.getKid())).collect(Collectors.toList());
      if (keys.isEmpty()) {
        result = null;
      } else {
        result = new ClientJwtConfiguration(null, new JsonWebKeySet<>(keys));
      }
    } else if (existingConfig.privateKeyJwt != null && tobeDeleted.privateKeyJwt != null) {
      List<JsonWebKey> existingKeys = new ArrayList<>(existingConfig.getPrivateKeyJwt().getKeys());
      existingKeys.removeAll(tobeDeleted.privateKeyJwt.getKeys());
      if (existingKeys.isEmpty()) {
        result = null;
      } else {
        result = new ClientJwtConfiguration(null, new JsonWebKeySet<>(existingKeys));
      }
    } else if (existingConfig.privateKeyJwtUrl != null && tobeDeleted.privateKeyJwtUrl != null) {
      if ("*".equals(tobeDeleted.privateKeyJwtUrl) || existingConfig.privateKeyJwtUrl.equals(tobeDeleted.privateKeyJwtUrl)) {
        result = null;
      } else {
        result = existingConfig;
      }
    }
    return result;
  }
}
