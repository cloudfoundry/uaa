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

import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Set;

import javax.net.ssl.KeyManagerFactory;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PasswordFinder;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;

public class SamlLoginServerKeyManager implements KeyManager {

    protected final static Logger logger = LoggerFactory.getLogger(SamlLoginServerKeyManager.class);
    private JKSKeyManager keyManager = null;

    public SamlLoginServerKeyManager(String key, String password, String certificate) {
        Security.addProvider(new BouncyCastleProvider());

        if (null == password) {
            password = "";
        }

        try {
            PEMReader reader = new PEMReader(new InputStreamReader(new ByteArrayInputStream(certificate.getBytes())));
            X509Certificate cert = (X509Certificate) reader.readObject();

            reader = new PEMReader(new InputStreamReader(new ByteArrayInputStream(key.getBytes())),
                            new StringPasswordFinder(password));
            KeyPair pkey = (KeyPair) reader.readObject();

            KeyStore keystore = KeyStore.getInstance("JKS");
            keystore.load(null);
            keystore.setCertificateEntry("service-provider-cert", cert);
            keystore.setKeyEntry("service-provider-cert", pkey.getPrivate(), password.toCharArray(),
                            new Certificate[] { cert });

            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(keystore, password.toCharArray());

            keyManager = new JKSKeyManager(keystore, Collections.singletonMap("service-provider-cert", password),
                            "service-provider-cert");

            if (null == keyManager) {
                throw new IllegalArgumentException(
                                "Could not load service provider certificate. Check serviceProviderKey and certificate parameters");
            }

            logger.info("Loaded service provider certificate " + keyManager.getDefaultCredentialName());
        } catch (Throwable t) {
            logger.error("Could not load certificate", t);
            throw new IllegalArgumentException(
                            "Could not load service provider certificate. Check serviceProviderKey and certificate parameters",
                            t);
        }
    }

    private class StringPasswordFinder implements PasswordFinder {

        private String password = null;

        public StringPasswordFinder(String password) {
            this.password = password;
        }

        @Override
        public char[] getPassword() {
            return password.toCharArray();
        }

    }

    @Override
    public Iterable<Credential> resolve(CriteriaSet criteria) throws SecurityException {
        return keyManager.resolve(criteria);
    }

    @Override
    public Credential resolveSingle(CriteriaSet criteria) throws SecurityException {
        return keyManager.resolveSingle(criteria);
    }

    @Override
    public Credential getCredential(String keyName) {
        return keyManager.getCredential(keyName);
    }

    @Override
    public Credential getDefaultCredential() {
        return keyManager.getDefaultCredential();
    }

    @Override
    public String getDefaultCredentialName() {
        return keyManager.getDefaultCredentialName();
    }

    @Override
    public Set<String> getAvailableCredentials() {
        return keyManager.getAvailableCredentials();
    }

    @Override
    public X509Certificate getCertificate(String alias) {
        return keyManager.getCertificate(alias);
    }

}
