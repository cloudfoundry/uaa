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
package org.cloudfoundry.identity.uaa.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static org.springframework.security.crypto.util.EncodingUtils.concatenate;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.codec.Utf8;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

/**
 * Wrapper around a slow password encoder that does a fast translation in memory only
 * This uses a hash to as a key to store a list of
 */
public class CachingPasswordEncoder implements PasswordEncoder {

    private final MessageDigest messageDigest;
    private final byte[] secret;
    private final byte[] salt;
    private final BytesKeyGenerator saltGenerator;
    private final int iterations;

    private int maxKeys = 1000;
    private int maxEncodedPasswords = 5;
    private boolean enabled = true;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    private final ConcurrentHashMap<CharSequence, Set<String>> cache = new ConcurrentHashMap<>();

    private BCryptPasswordEncoder passwordEncoder;

    public CachingPasswordEncoder() throws NoSuchAlgorithmException {
        messageDigest = MessageDigest.getInstance("SHA-256");
        this.secret = Utf8.encode(new RandomValueStringGenerator().generate());
        this.saltGenerator = KeyGenerators.secureRandom();
        this.salt = saltGenerator.generateKey();
        iterations = 25;
    }

    public PasswordEncoder getPasswordEncoder() {
        return passwordEncoder;
    }

    public void setPasswordEncoder(BCryptPasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public String encode(CharSequence rawPassword) {
        //encode we always use the Bcrypt mechanism
        return getPasswordEncoder().encode(rawPassword);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (isEnabled()) {
            String cacheKey = cacheEncode(rawPassword);
            return internalMatches(cacheKey, rawPassword, encodedPassword);
        } else {
            return getPasswordEncoder().matches(rawPassword, encodedPassword);
        }
    }

    private Set<String> getOrCreateHashList(String cacheKey) {
        cache.putIfAbsent(cacheKey, Collections.synchronizedSet(new LinkedHashSet<String>()));
        if (cache.size()>getMaxKeys()) {
            //this should not happen if properly tuned.
            cache.clear();
        }
        Set<String> result = cache.get(cacheKey);
        return result;
    }

    private boolean internalMatches(String cacheKey, CharSequence rawPassword, String encodedPassword) {
        Set<String> cacheValue = cache.get(cacheKey);
        boolean result = false;
        for (String encoded : cacheValue!=null ? cacheValue : Collections.<String>emptyList()) {
            if (hashesEquals(encoded, encodedPassword)) {
                result = true;
                break;
            }
        }
        if (!result) {
            String encoded = BCrypt.hashpw(rawPassword.toString(), encodedPassword);
            if (hashesEquals(encoded, encodedPassword)) {
                result = true;
                cacheValue = getOrCreateHashList(cacheKey);
                if (cacheValue!=null) {
                    cacheValue.add(encoded);
                    //this list should never grow very long.
                    //Only if you store multiple versions of the same password more than once
                    if (cacheValue.size() > getMaxEncodedPasswords()) {
                        cacheValue.clear();
                    }
                }
            }
        }
        return result;
    }


    protected String cacheEncode(CharSequence rawPassword) {
        byte[] digest = digest(rawPassword);
        return new String(Hex.encode(digest));
    }

    private byte[] digest(CharSequence rawPassword) {
        byte[] digest = digest(concatenate(salt, secret, Utf8.encode(rawPassword)));
        return concatenate(salt, digest);
    }

    private byte[] digest(byte[] value) {
        synchronized (messageDigest) {
            for (int i = 0; i < iterations; i++) {
                value = messageDigest.digest(value);
            }
            return value;
        }
    }

    private boolean hashesEquals(String a, String b) {
        char[] caa = a.toCharArray();
        char[] cab = b.toCharArray();

        if (caa.length != cab.length) {
            return false;
        }

        byte ret = 0;
        for (int i = 0; i < caa.length; i++) {
            ret |= caa[i] ^ cab[i];
        }
        return ret == 0;
    }

    public int getMaxKeys() {
        return maxKeys;
    }

    public void setMaxKeys(int maxKeys) {
        this.maxKeys = maxKeys;
    }

    public int getMaxEncodedPasswords() {
        return maxEncodedPasswords;
    }

    public void setMaxEncodedPasswords(int maxEncodedPasswords) {
        this.maxEncodedPasswords = maxEncodedPasswords;
    }

    public int getNumberOfKeys() {
        return cache.size();
    }
}
