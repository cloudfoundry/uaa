/*
 * *****************************************************************************
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

import lombok.extern.slf4j.Slf4j;
import org.cloudfoundry.identity.uaa.saml.SamlKey;
import org.cloudfoundry.identity.uaa.util.KeyWithCert;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;

import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Slf4j
public final class SamlKeyManagerFactory {
    private final SamlConfigProps samlConfigProps;

    public SamlKeyManagerFactory(SamlConfigProps samlConfigProps) {
        this.samlConfigProps = samlConfigProps;
    }

    public SamlKeyManager getKeyManager(SamlConfig config) {
        boolean hasKeys = Optional.ofNullable(config)
                .map(SamlConfig::getKeys)
                .map(k -> !k.isEmpty())
                .orElse(false);

        if (hasKeys) {
            return new SamlConfigSamlKeyManagerImpl(config);
        }
        // fall back to default keys in samlConfigProps
        return new SamlConfigPropsSamlKeyManagerImpl(samlConfigProps);
    }

    //*****************************
    // Key Manager Implementations
    //*****************************

    abstract static class BaseSamlKeyManagerImpl implements SamlKeyManager {

        protected List<KeyWithCert> convertList(List<SamlKey> samlKeys) {
            List<KeyWithCert> result = new ArrayList<>();
            for (SamlKey k : samlKeys) {
                try {
                    result.add(convertKey(k));
                } catch (CertificateRuntimeException e) {
                    // already logged in convertKey
                }
            }

            return result;
        }

        protected static KeyWithCert convertKey(SamlKey k) {
            try {
                return KeyWithCert.fromSamlKey(k);
            } catch (CertificateException e) {
                log.error("Error converting key with cert", e);
                throw new CertificateRuntimeException(e);
            }
        }
    }

    static class SamlConfigSamlKeyManagerImpl extends BaseSamlKeyManagerImpl {

        private final SamlConfig samlConfig;

        SamlConfigSamlKeyManagerImpl(SamlConfig samlConfig) {
            this.samlConfig = samlConfig;
        }

        @Override
        public KeyWithCert getCredential(String keyName) {
            return convertKey(samlConfig.getKeys().get(keyName));
        }

        @Override
        public KeyWithCert getDefaultCredential() {
            return convertKey(samlConfig.getActiveKey());
        }

        @Override
        public String getDefaultCredentialName() {
            return samlConfig.getActiveKeyId();
        }

        @Override
        public List<KeyWithCert> getAvailableCredentials() {
            return convertList(samlConfig.getKeyList());
        }

        @Override
        public List<String> getAvailableCredentialIds() {
            List<String> keyList = new ArrayList<>();
            String activeKeyId = getDefaultCredentialName();
            Optional.ofNullable(activeKeyId).ifPresent(keyList::add);
            keyList.addAll(samlConfig.getKeys().keySet().stream()
                    .filter(k -> !k.equals(activeKeyId))
                    .toList());

            return Collections.unmodifiableList(keyList);
        }
    }

    static class SamlConfigPropsSamlKeyManagerImpl extends BaseSamlKeyManagerImpl {

        private final SamlConfigProps samlConfigProps;

        SamlConfigPropsSamlKeyManagerImpl(SamlConfigProps samlConfigProps) {
            this.samlConfigProps = samlConfigProps;
        }

        @Override
        public KeyWithCert getCredential(String keyName) {
            return convertKey(samlConfigProps.getKeys().get(keyName));
        }

        @Override
        public KeyWithCert getDefaultCredential() {
            return convertKey(samlConfigProps.getActiveSamlKey());
        }

        @Override
        public String getDefaultCredentialName() {
            return samlConfigProps.getActiveKeyId();
        }

        @Override
        public List<KeyWithCert> getAvailableCredentials() {
            List<SamlKey> keyList = new ArrayList<>();
            String activeKeyId = getDefaultCredentialName();
            Optional.ofNullable(samlConfigProps.getActiveSamlKey()).ifPresent(keyList::add);
            keyList.addAll(samlConfigProps.getKeys().entrySet().stream()
                    .filter(e -> !e.getKey().equals(activeKeyId))
                    .map(Map.Entry::getValue)
                    .toList());

            if (keyList.isEmpty()) {
                SamlKey legacyKey = null;
                if (samlConfigProps.getServiceProviderKey() != null && samlConfigProps.getServiceProviderCertificate() != null) {
                    legacyKey = new SamlKey(samlConfigProps.getServiceProviderKey(), samlConfigProps.getServiceProviderKeyPassword(),
                            samlConfigProps.getServiceProviderCertificate());
                    log.warn("SAML should be setup with key map structure.");
                } else if (samlConfigProps.getLegacyServiceProviderKey() != null && samlConfigProps.getLegacyServiceProviderCertificate() != null) {
                    legacyKey = new SamlKey(samlConfigProps.getLegacyServiceProviderKey(), samlConfigProps.getLegacyServiceProviderKeyPassword(),
                            samlConfigProps.getLegacyServiceProviderCertificate());
                    log.error("This section is deprecated and will not work in near future anymore.");
                }
                if (legacyKey != null) {
                    keyList.add(legacyKey);
                }
            }
            return convertList(keyList);
        }

        @Override
        public List<String> getAvailableCredentialIds() {
            List<String> keyList = new ArrayList<>();
            String activeKeyId = samlConfigProps.getActiveKeyId();
            Optional.ofNullable(activeKeyId).ifPresent(keyList::add);
            keyList.addAll(samlConfigProps.getKeys().keySet().stream()
                    .filter(k -> !k.equals(activeKeyId))
                    .toList());

            return Collections.unmodifiableList(keyList);
        }
    }
}
