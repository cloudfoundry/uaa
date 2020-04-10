package org.cloudfoundry.identity.uaa.oauth.jwt;

import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.security.jwt.crypto.sign.RsaSigner;

public class CommonSigner implements Signer {

  private final org.springframework.security.jwt.crypto.sign.Signer delegate;
  private final String keyId;
  private String keyURL;

  public CommonSigner(String keyId, String signingKey, String keyURL) {
    if (signingKey == null) {
      throw new IllegalArgumentException(signingKey);
    } else if (isAssymetricKey(signingKey)) {
      delegate = new RsaSigner(signingKey);
    } else {
      delegate = new MacSigner(signingKey);
    }

    this.keyId = keyId;
    this.keyURL = keyURL;
  }

  private static boolean isAssymetricKey(String key) {
    return key.startsWith("-----BEGIN");
  }

  @Override
  public String keyId() {
    return keyId;
  }

  @Override
  public String keyURL() {
    return keyURL;
  }

  @Override
  public byte[] sign(byte[] bytes) {
    return delegate.sign(bytes);
  }

  @Override
  public String algorithm() {
    return JwtAlgorithms.sigAlg(delegate.algorithm());
  }

  public String getJavaAlgorithm() {
    return delegate.algorithm();
  }
}
