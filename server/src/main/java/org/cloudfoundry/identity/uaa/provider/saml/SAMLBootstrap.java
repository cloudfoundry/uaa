/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */
package org.cloudfoundry.identity.uaa.provider.saml;

import org.opensaml.Configuration;
import org.opensaml.xml.security.BasicSecurityConfiguration;
import org.opensaml.xml.signature.SignatureConstants;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.BeansException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

 /* Enables SHA256 or SHA512 Digital Signatures and Signature Reference Digests to SAML Requests & Assertions
  */
public class SAMLBootstrap extends org.springframework.security.saml.SAMLBootstrap {

    public static final String DEFAULT_ALGORITHM = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1;
    String signatureUrl =  DEFAULT_ALGORITHM;
    
    protected final static Logger log = LoggerFactory.getLogger(SAMLBootstrap.class);
        
    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
      super.postProcessBeanFactory(beanFactory);
      init();
    }
        
    protected void init() {
      BasicSecurityConfiguration config = (BasicSecurityConfiguration) Configuration.getGlobalSecurityConfiguration();
      config.registerSignatureAlgorithmURI("RSA", signatureUrl);
      if (signatureUrl.equals(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1))
        config.setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA1);
      else if (signatureUrl.equals(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256))
        config.setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA256);
      else if (signatureUrl.equals(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512))
        config.setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA512);
    }
    
    public void setSignatureAlgorithm(String url) {
      if (SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1.equals(url) ||
        SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256.equals(url) ||
        SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512.equals(url)) {
        this.signatureUrl = url;
        log.info("Using SAML XML digital signature: " + url);
      }
      else {
        log.warn("Invalid SAML XML digital signature: " + url + ", defaulting to " + this.signatureUrl);
      }
    }
}
