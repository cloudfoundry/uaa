package org.cloudfoundry.identity.uaa.oauth.token;

import com.fasterxml.jackson.annotation.JsonIgnore;
import java.util.Map;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;

/**
 * Use {@link JsonWebKey}.
 */
@Deprecated
public class VerificationKeyResponse extends JsonWebKey {

  public VerificationKeyResponse(Map<String, Object> json) {
    super(json);
  }

  @JsonIgnore
  public String getId() {
    return getKid();
  }

  @JsonIgnore
  public String getAlgorithm() {
    return (String) getKeyProperties().get("alg");
  }

  @JsonIgnore
  public String getKey() {
    return (String) getKeyProperties().get("value");
  }

  @JsonIgnore
  public String getType() {
    return getKty().name();
  }

  @JsonIgnore
  public String getKeyUse() {
    return getUse().name();
  }

  @JsonIgnore
  public String getModulus() {
    return (String) getKeyProperties().get("n");
  }

  @JsonIgnore
  public String getExponent() {
    return (String) getKeyProperties().get("e");
  }
}
