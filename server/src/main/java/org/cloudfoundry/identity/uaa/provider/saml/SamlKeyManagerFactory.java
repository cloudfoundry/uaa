/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.util.KeyWithCert;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.util.StringUtils;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;

public final class SamlKeyManagerFactory {

    protected final static Logger logger = LoggerFactory.getLogger(SamlKeyManagerFactory.class);

    private SamlKeyManagerFactory() {}

    public static KeyManager getKeyManager(SamlConfig config) {
        return getKeyManager(config.getPrivateKey(), config.getPrivateKeyPassword(), config.getCertificate());
    }

    public static KeyManager getKeyManager(String key, String password, String certificate) {
        if(!StringUtils.hasText(key)) return null;

        if (null == password) {
            password = "";
        }

        try {
            KeyWithCert keyWithCert = new KeyWithCert(key, password, certificate);
            X509Certificate cert = keyWithCert.getCert();
            KeyPair pkey = keyWithCert.getPkey();

            KeyStore keystore = KeyStore.getInstance("JKS");
            keystore.load(null);
            String alias = "service-provider-cert-" + IdentityZoneHolder.get().getId();
            keystore.setCertificateEntry(alias, cert);
            keystore.setKeyEntry(alias, pkey.getPrivate(), password.toCharArray(),
                    new Certificate[] { cert });

            JKSKeyManager keyManager = new JKSKeyManager(keystore, Collections.singletonMap(alias, password),
                    alias);

            if (null == keyManager) {
                throw new IllegalArgumentException(
                        "Could not load service provider certificate. Check serviceProviderKey and certificate parameters");
            }

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
