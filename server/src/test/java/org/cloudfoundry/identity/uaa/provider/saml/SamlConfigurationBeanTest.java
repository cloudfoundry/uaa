package org.cloudfoundry.identity.uaa.provider.saml;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;
import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.security.BasicSecurityConfiguration;
import org.opensaml.xml.signature.SignatureConstants;

import java.security.Security;

import static org.junit.Assert.assertEquals;

public class SamlConfigurationBeanTest {

    @BeforeClass
    public static void initVM() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        DefaultBootstrap.bootstrap();
    }

    @Test
    public void testSHA1SignatureAlgorithm() {
        SamlConfigurationBean samlConfigurationBean = new SamlConfigurationBean();
        samlConfigurationBean.setSignatureAlgorithm(SamlConfigurationBean.SignatureAlgorithm.SHA1);
        samlConfigurationBean.afterPropertiesSet();

        BasicSecurityConfiguration config = (BasicSecurityConfiguration) Configuration.getGlobalSecurityConfiguration();
        assertEquals(SignatureConstants.ALGO_ID_DIGEST_SHA1, config.getSignatureReferenceDigestMethod());
        assertEquals(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1, config.getSignatureAlgorithmURI("RSA"));
    }

    @Test
    public void testSHA256SignatureAlgorithm() {
        SamlConfigurationBean samlConfigurationBean = new SamlConfigurationBean();
        samlConfigurationBean.setSignatureAlgorithm(SamlConfigurationBean.SignatureAlgorithm.SHA256);
        samlConfigurationBean.afterPropertiesSet();

        BasicSecurityConfiguration config = (BasicSecurityConfiguration) Configuration.getGlobalSecurityConfiguration();
        assertEquals(SignatureConstants.ALGO_ID_DIGEST_SHA256, config.getSignatureReferenceDigestMethod());
        assertEquals(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256, config.getSignatureAlgorithmURI("RSA"));
    }

    @Test
    public void testSHA512SignatureAlgorithm() {
        SamlConfigurationBean samlConfigurationBean = new SamlConfigurationBean();
        samlConfigurationBean.setSignatureAlgorithm(SamlConfigurationBean.SignatureAlgorithm.SHA512);
        samlConfigurationBean.afterPropertiesSet();

        BasicSecurityConfiguration config = (BasicSecurityConfiguration) Configuration.getGlobalSecurityConfiguration();
        assertEquals(SignatureConstants.ALGO_ID_DIGEST_SHA512, config.getSignatureReferenceDigestMethod());
        assertEquals(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512, config.getSignatureAlgorithmURI("RSA"));
    }

}
