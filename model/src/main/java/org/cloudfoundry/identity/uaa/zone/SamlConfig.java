/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.zone;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import org.cloudfoundry.identity.uaa.saml.SamlKey;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.springframework.util.StringUtils.hasText;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
@Data
public class SamlConfig {
    public static final String LEGACY_KEY_ID = "legacy-saml-key";

    private boolean requestSigned = true;
    private boolean wantAssertionSigned = true;
    private String activeKeyId;
    private Map<String, SamlKey> keys = new HashMap<>();
    private String entityID;
    private boolean disableInResponseToCheck;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public String getEntityID() {
        return entityID;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public void setEntityID(String entityID) {
        this.entityID = entityID;
    }

    @JsonProperty("certificate")
    public void setCertificate(String certificate) {
        if (hasText(certificate)) {
            keys.computeIfAbsent(LEGACY_KEY_ID, k -> new SamlKey());
        }
        keys.computeIfPresent(LEGACY_KEY_ID, (k, v) -> {
            v.setCertificate(certificate);
            return v;
        });
    }

    @JsonProperty("privateKey")
    public void setPrivateKey(String privateKey) {
        if (hasText(privateKey)) {
            keys.computeIfAbsent(LEGACY_KEY_ID, k -> new SamlKey());
        }
        keys.computeIfPresent(LEGACY_KEY_ID, (k, v) -> {
            v.setKey(privateKey);
            return v;
        });
    }

    @JsonProperty("privateKeyPassword")
    public void setPrivateKeyPassword(String privateKeyPassword) {
        if (hasText(privateKeyPassword)) {
            keys.computeIfAbsent(LEGACY_KEY_ID, k -> new SamlKey());
        }
        keys.computeIfPresent(LEGACY_KEY_ID, (k, v) -> {
            v.setPassphrase(privateKeyPassword);
            return v;
        });
    }

    @JsonProperty("certificate")
    public String getCertificate() {
        return Optional.ofNullable(keys.get(LEGACY_KEY_ID))
                .map(SamlKey::getCertificate)
                .orElse(null);
    }

    @JsonProperty
    public String getPrivateKey() {
        return Optional.ofNullable(keys.get(LEGACY_KEY_ID))
                .map(SamlKey::getKey)
                .orElse(null);
    }

    @JsonProperty
    public String getPrivateKeyPassword() {
        return Optional.ofNullable(keys.get(LEGACY_KEY_ID))
                .map(SamlKey::getPassphrase)
                .orElse(null);
    }

    public String getActiveKeyId() {
        if (hasText(activeKeyId)) {
            return activeKeyId;
        }
        return hasLegacyKey() ? LEGACY_KEY_ID : null;
    }

    @JsonIgnore
    public SamlKey getActiveKey() {
        String keyId = getActiveKeyId();
        return keyId != null ? keys.get(keyId) : null;
    }

    public void setActiveKeyId(String activeKeyId) {
        if (!LEGACY_KEY_ID.equals(activeKeyId)) {
            this.activeKeyId = activeKeyId;
        }
    }

    /**
     * @return a map of all keys by keyName
     */
    public Map<String, SamlKey> getKeys() {
        return Collections.unmodifiableMap(keys);
    }

    /**
     * @return the list of keys, with the active key first.
     */
    @JsonIgnore
    public List<SamlKey> getKeyList() {
        List<SamlKey> keyList = new ArrayList<>();
        String resolvedActiveKeyId = getActiveKeyId();
        Optional.ofNullable(getActiveKey()).ifPresent(keyList::add);
        keyList.addAll(keys.entrySet().stream()
                .filter(e -> !e.getKey().equals(resolvedActiveKeyId))
                .map(Map.Entry::getValue)
                .toList());
        return Collections.unmodifiableList(keyList);
    }

    public void setKeys(Map<String, SamlKey> keys) {
        this.keys = new HashMap<>(keys);
    }

    @JsonIgnore
    public void addAndActivateKey(String keyId, SamlKey key) {
        addKey(keyId, key);
        this.activeKeyId = keyId;
    }

    @JsonIgnore
    public void addKey(String keyId, SamlKey key) {
        keys.put(keyId, key);
    }

    @JsonIgnore
    protected boolean hasLegacyKey() {
        return keys.get(LEGACY_KEY_ID) != null;
    }

    @JsonIgnore
    public SamlKey removeKey(String keyId) {
        return keys.remove(keyId);
    }
}
