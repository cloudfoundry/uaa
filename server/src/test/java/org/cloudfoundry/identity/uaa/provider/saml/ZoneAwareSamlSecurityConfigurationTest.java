package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Test;
import org.opensaml.xml.signature.SignatureConstants;

import static org.cloudfoundry.identity.uaa.zone.SamlConfig.SignatureAlgorithm.SHA1;
import static org.cloudfoundry.identity.uaa.zone.SamlConfig.SignatureAlgorithm.SHA256;
import static org.cloudfoundry.identity.uaa.zone.SamlConfig.SignatureAlgorithm.SHA512;
import static org.junit.Assert.assertEquals;

public class ZoneAwareSamlSecurityConfigurationTest {
    ZoneAwareSamlSecurityConfiguration config = new ZoneAwareSamlSecurityConfiguration();

  @Test
  public void testSHA1SignatureAlgorithm() {
    IdentityZoneHolder.get().getConfig().getSamlConfig().setSignatureAlgorithm(SHA1);

    assertEquals(SignatureConstants.ALGO_ID_DIGEST_SHA1, config.getSignatureReferenceDigestMethod());
    assertEquals(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1, config.getSignatureAlgorithmURI("RSA"));
  }

  @Test
  public void testSHA256SignatureAlgorithm() {
    IdentityZoneHolder.get().getConfig().getSamlConfig().setSignatureAlgorithm(SHA256 );

    assertEquals(SignatureConstants.ALGO_ID_DIGEST_SHA256, config.getSignatureReferenceDigestMethod());
    assertEquals(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256, config.getSignatureAlgorithmURI("RSA"));
  }

  @Test
  public void testSHA512SignatureAlgorithm() {
    IdentityZoneHolder.get().getConfig().getSamlConfig().setSignatureAlgorithm(SHA512 );

    assertEquals(SignatureConstants.ALGO_ID_DIGEST_SHA512, config.getSignatureReferenceDigestMethod());
    assertEquals(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512, config.getSignatureAlgorithmURI("RSA"));
  }

  @Test
  public void testNoSignatureAlgorithmIsSet() {
    IdentityZoneHolder.get().getConfig().getSamlConfig().setSignatureAlgorithm(null);
    config.setDefaultSignatureAlgorithm(SHA256);
    assertEquals(SignatureConstants.ALGO_ID_DIGEST_SHA256, config.getSignatureReferenceDigestMethod());
    assertEquals(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256, config.getSignatureAlgorithmURI("RSA"));
  }
}