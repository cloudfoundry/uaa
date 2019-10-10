package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.SamlConfig.SignatureAlgorithm;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.security.BasicSecurityConfiguration;
import org.opensaml.xml.signature.SignatureConstants;

public class ZoneAwareSamlSecurityConfiguration extends BasicSecurityConfiguration{

    private SignatureAlgorithm defaultSignatureAlgorithm;

    @Override
    public String getSignatureAlgorithmURI(String jcaAlgorithmName) {
        resolveSignatureAlgorithm();
        return super.getSignatureAlgorithmURI(jcaAlgorithmName);
    }

    @Override
    public String getSignatureReferenceDigestMethod() {
        resolveSignatureAlgorithm();
        return super.getSignatureReferenceDigestMethod();
    }

    private void resolveSignatureAlgorithm() {
        SignatureAlgorithm signatureAlgorithm = IdentityZoneHolder.get().getConfig().getSamlConfig().getSignatureAlgorithm();
        if(signatureAlgorithm == null) {
            signatureAlgorithm = defaultSignatureAlgorithm;
        }
        resolveSignatureAlgorithm(signatureAlgorithm);
    }
    @Override
    public Integer getSignatureHMACOutputLength() {
        return  Configuration.getGlobalSecurityConfiguration().getSignatureHMACOutputLength();
    }

    @Override
    public String getSignatureCanonicalizationAlgorithm() {
        return Configuration.getGlobalSecurityConfiguration().getSignatureCanonicalizationAlgorithm();
    }

    private void resolveSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
        switch (signatureAlgorithm) {
          case SHA1:
            registerSignatureAlgorithmURI("RSA", SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
            setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA1);
            break;
          case SHA256:
            registerSignatureAlgorithmURI("RSA", SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
            setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA256);
            break;
          case SHA512:
            registerSignatureAlgorithmURI("RSA", SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512);
            setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA512);
            break;
        }
    }

    public void setDefaultSignatureAlgorithm(SignatureAlgorithm defaultSignatureAlgorithm) {
        this.defaultSignatureAlgorithm = defaultSignatureAlgorithm;
    }
}