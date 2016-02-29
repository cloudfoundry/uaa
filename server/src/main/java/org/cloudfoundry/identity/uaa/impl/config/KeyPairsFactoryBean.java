/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.impl.config;

import org.cloudfoundry.identity.uaa.zone.SigningKeysMap;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;


public class KeyPairsFactoryBean {
    private Map<String,Map<String,String>> keyPairsMap;

    public KeyPairsFactoryBean(Map<String, ? extends Map<String, String>> map, Map<String, String> legacyKeyPair) throws NoSuchAlgorithmException {
        Map<String, Map<String,String>> keys = new HashMap<>();
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(legacyKeyPair.get("signingKey").getBytes());
        BigInteger number = new BigInteger(1, digest);
        String keyId = number.toString();
        keys.put(keyId, legacyKeyPair);
        keys.putAll(map);
        this.keyPairsMap = keys;
    }

    public SigningKeysMap getKeyPairsMap() {
        return new SigningKeysMap(keyPairsMap);
    }
}
