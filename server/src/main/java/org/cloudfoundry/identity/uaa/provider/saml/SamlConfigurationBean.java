// TODO: add legal boilerplate
package org.cloudfoundry.identity.uaa.provider.saml;

import org.opensaml.xml.Configuration;
import org.opensaml.xml.security.BasicSecurityConfiguration;
import org.opensaml.xml.signature.SignatureConstants;
import org.springframework.beans.factory.InitializingBean;


public class SamlConfigurationBean implements InitializingBean {
  private SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.SHA1;

  public void setSignatureAlgorithm(SignatureAlgorithm s) {
    signatureAlgorithm = s;
  }

  @Override
  public void afterPropertiesSet() throws Exception {
    BasicSecurityConfiguration config = (BasicSecurityConfiguration) Configuration.getGlobalSecurityConfiguration();
    switch (signatureAlgorithm) {
      case SHA1:
        config.registerSignatureAlgorithmURI("RSA", SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
        config.setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA1);
        break;
      case SHA256:
        config.registerSignatureAlgorithmURI("RSA", SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        config.setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA256);
        break;
      case SHA512:
        config.registerSignatureAlgorithmURI("RSA", SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512);
        config.setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA512);
        break;
    }
  }

  public enum SignatureAlgorithm {
    SHA1,
    SHA256,
    SHA512
  }
}
