package org.cloudfoundry.identity.uaa.provider.saml;

import static java.util.Optional.ofNullable;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import org.cloudfoundry.identity.uaa.saml.SamlKey;
import org.cloudfoundry.identity.uaa.util.KeyWithCert;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;

public final class SamlKeyManagerFactory {

  protected static final Logger logger = LoggerFactory.getLogger(SamlKeyManagerFactory.class);

  public SamlKeyManagerFactory() {}

  public KeyManager getKeyManager(SamlConfig config) {
    return getKeyManager(config.getKeys(), config.getActiveKeyId());
  }

  private KeyManager getKeyManager(Map<String, SamlKey> keys, String activeKeyId) {
    SamlKey activeKey = keys.get(activeKeyId);

    if (activeKey == null) {
      return null;
    }

    try {
      KeyStore keystore = KeyStore.getInstance("JKS");
      keystore.load(null);
      Map<String, String> aliasPasswordMap = new HashMap<>();
      for (Map.Entry<String, SamlKey> entry : keys.entrySet()) {
        String password = ofNullable(entry.getValue().getPassphrase()).orElse("");
        KeyWithCert keyWithCert =
            entry.getValue().getKey() == null
                ? new KeyWithCert(entry.getValue().getCertificate())
                : new KeyWithCert(
                    entry.getValue().getKey(), password, entry.getValue().getCertificate());

        X509Certificate certificate = keyWithCert.getCertificate();

        String alias = entry.getKey();
        keystore.setCertificateEntry(alias, certificate);

        PrivateKey privateKey = keyWithCert.getPrivateKey();
        if (privateKey != null) {
          keystore.setKeyEntry(
              alias, privateKey, password.toCharArray(), new Certificate[] {certificate});
          aliasPasswordMap.put(alias, password);
        }
      }

      JKSKeyManager keyManager = new JKSKeyManager(keystore, aliasPasswordMap, activeKeyId);

      logger.info("Loaded service provider certificate " + keyManager.getDefaultCredentialName());

      return keyManager;
    } catch (Throwable t) {
      logger.error("Could not load certificate", t);
      throw new IllegalArgumentException(
          "Could not load service provider certificate. Check serviceProviderKey and certificate parameters",
          t);
    }
  }
}
