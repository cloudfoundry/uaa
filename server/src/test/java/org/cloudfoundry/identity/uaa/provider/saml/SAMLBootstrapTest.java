package org.cloudfoundry.identity.uaa.provider.saml;

import org.junit.Test;
import static org.junit.Assert.assertEquals;

import org.opensaml.Configuration;
import org.opensaml.xml.security.BasicSecurityConfiguration;
import org.opensaml.xml.signature.SignatureConstants;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.BeansException;

public class SAMLBootstrapTest {

    @Test
    public void testSHA1SignatureAlgorithm()  {
      SAMLBootstrap boot = new SAMLBootstrap();
      boot.setSignatureAlgorithm( SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1 );
      boot.init();
      
      BasicSecurityConfiguration config = (BasicSecurityConfiguration) Configuration.getGlobalSecurityConfiguration();
      assertEquals(SignatureConstants.ALGO_ID_DIGEST_SHA1, config.getSignatureReferenceDigestMethod());
      assertEquals(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1, config.getSignatureAlgorithmURI("RSA"));
      
    }
    
    @Test
    public void testSHA256SignatureAlgorithm()  {
      SAMLBootstrap boot = new SAMLBootstrap();
      boot.setSignatureAlgorithm( SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256 );
      boot.init();
      
      BasicSecurityConfiguration config = (BasicSecurityConfiguration) Configuration.getGlobalSecurityConfiguration();
      assertEquals(SignatureConstants.ALGO_ID_DIGEST_SHA256, config.getSignatureReferenceDigestMethod());
      assertEquals(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256, config.getSignatureAlgorithmURI("RSA"));      
    }
        
    @Test
    public void testSHA512SignatureAlgorithm()  {
      SAMLBootstrap boot = new SAMLBootstrap();
      boot.setSignatureAlgorithm( SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512 );
      boot.init();
      
      BasicSecurityConfiguration config = (BasicSecurityConfiguration) Configuration.getGlobalSecurityConfiguration();
      assertEquals(SignatureConstants.ALGO_ID_DIGEST_SHA512, config.getSignatureReferenceDigestMethod());
      assertEquals(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512, config.getSignatureAlgorithmURI("RSA"));      
    }
    
    @Test
    public void testBadSignatureAlgorithm()  {
      SAMLBootstrap boot = new SAMLBootstrap();
      boot.setSignatureAlgorithm( "bad" );
      boot.init();
      
      BasicSecurityConfiguration config = (BasicSecurityConfiguration) Configuration.getGlobalSecurityConfiguration();
      assertEquals(SignatureConstants.ALGO_ID_DIGEST_SHA1, config.getSignatureReferenceDigestMethod());
      assertEquals(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1, config.getSignatureAlgorithmURI("RSA"));     
    }
}