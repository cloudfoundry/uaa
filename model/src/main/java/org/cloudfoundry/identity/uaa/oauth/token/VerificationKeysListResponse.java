package org.cloudfoundry.identity.uaa.oauth.token;

import java.util.List;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKeySet;

/**
 * Use {@link JsonWebKeySet}.
 */
@Deprecated
public class VerificationKeysListResponse extends JsonWebKeySet<VerificationKeyResponse> {

  public VerificationKeysListResponse(List<VerificationKeyResponse> keys) {
    super(keys);
  }
}
