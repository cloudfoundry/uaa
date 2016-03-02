package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.util.KeyWithCert;
import org.springframework.util.StringUtils;

import java.security.GeneralSecurityException;

/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
public class GeneralIdentityZoneConfigurationValidator implements IdentityZoneConfigurationValidator {
    @Override
    public IdentityZoneConfiguration validate(IdentityZoneConfiguration config, Mode mode) throws InvalidIdentityZoneConfigurationException {
        SamlConfig samlConfig;
        TokenPolicy tokenPolicy;
        if(mode ==  Mode.CREATE || mode == Mode.MODIFY) {
            try {
                if ((samlConfig = config.getSamlConfig()) != null) {
                    String samlSpCert = samlConfig.getCertificate();
                    String samlSpKey = samlConfig.getPrivateKey();
                    String samlSpkeyPassphrase = samlConfig.getPrivateKeyPassword();
                    if (samlSpKey != null && samlSpCert != null) {
                        KeyWithCert keyWithCert = new KeyWithCert(samlSpKey, samlSpkeyPassphrase, samlSpCert);
                    }
                }
                if ((tokenPolicy = config.getTokenPolicy()) != null && tokenPolicy.getKeys() !=null) {
                    tokenPolicy.getKeys().entrySet().stream().forEach(e -> {
                        if(!StringUtils.hasText(e.getValue()) || !StringUtils.hasText(e.getKey())) {
                            throw new IllegalArgumentException("KeyId and Signing key should not be null or empty");
                        }
                    });
                }
            } catch(GeneralSecurityException ex) {
                throw new InvalidIdentityZoneConfigurationException("There is a security problem with the SAML SP configuration.", ex);
            }
        }

        return config;
    }
}
