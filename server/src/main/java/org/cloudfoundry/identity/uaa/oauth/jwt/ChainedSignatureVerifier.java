package org.cloudfoundry.identity.uaa.oauth.jwt;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKeySet;
import org.springframework.security.jwt.crypto.sign.InvalidSignatureException;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;

public class ChainedSignatureVerifier implements SignatureVerifier {

  private final List<SignatureVerifier> delegates;

  public ChainedSignatureVerifier(JsonWebKeySet<? extends JsonWebKey> keys) {
    if (keys == null || keys.getKeys() == null || keys.getKeys().isEmpty()) {
      throw new IllegalArgumentException("keys cannot be null or empty");
    }
    List<SignatureVerifier> ds = new ArrayList<>(keys.getKeys().size());
    for (JsonWebKey key : keys.getKeys()) {
      ds.add(new CommonSignatureVerifier(key.getValue()));
    }
    delegates = Collections.unmodifiableList(ds);
  }

  public ChainedSignatureVerifier(List<SignatureVerifier> delegates) {
    this.delegates = delegates;
  }

  @Override
  public void verify(byte[] content, byte[] signature) {
    Exception last = new InvalidSignatureException("No matching keys found.");
    for (SignatureVerifier delegate : delegates) {
      try {
        delegate.verify(content, signature);
        // success
        return;
      } catch (Exception e) {
        last = e;
      }
    }
    throw (last instanceof RuntimeException) ? (RuntimeException) last : new RuntimeException(last);
  }

  @Override
  public String algorithm() {
    return null;
  }
}
