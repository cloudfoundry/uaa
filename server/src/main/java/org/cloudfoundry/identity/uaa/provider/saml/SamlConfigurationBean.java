/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */
package org.cloudfoundry.identity.uaa.provider.saml;

import java.time.Clock;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.saml.spi.opensaml.OpenSamlImplementation;


public class SamlConfigurationBean implements InitializingBean {
  private SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.SHA1;
  private Clock clock = Clock.systemUTC();

  public void setSignatureAlgorithm(SignatureAlgorithm s) {
    signatureAlgorithm = s;
  }

  @Override
  public void afterPropertiesSet() throws Exception {
      new OpenSamlImplementation(clock).init();
  }

  public enum SignatureAlgorithm {
    SHA1,
    SHA256,
    SHA512
  }
}
