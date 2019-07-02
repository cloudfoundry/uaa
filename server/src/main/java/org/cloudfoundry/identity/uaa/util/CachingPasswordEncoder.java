package org.cloudfoundry.identity.uaa.util;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.codec.Utf8;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;

import static org.springframework.security.crypto.util.EncodingUtils.concatenate;

/**
 * Wrapper around a slow password encoder that does a fast translation in memory only
 * This uses a hash to as a key to store a list of
 */
public class CachingPasswordEncoder implements PasswordEncoder {

    private final MessageDigest messageDigest;
    private final byte[] secret;
    private final byte[] salt;
    private final int iterations;

    private int maxKeys = 1000;
    private int maxEncodedPasswords = 5;
    private boolean enabled = true;
    private int expiryInSeconds = 300;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    private volatile Cache<CharSequence, Set<String>> cache = null;

    private final PasswordEncoder passwordEncoder;

    CachingPasswordEncoder(final PasswordEncoder passwordEncoder) throws NoSuchAlgorithmException {
        this.passwordEncoder = passwordEncoder;
        messageDigest = MessageDigest.getInstance("SHA-256");
        this.secret = Utf8.encode(new RandomValueStringGenerator().generate());
        this.salt = KeyGenerators.secureRandom().generateKey();
        iterations = 25;
        buildCache();
    }

    @Override
    public String encode(CharSequence rawPassword) throws AuthenticationException {
        // we always use the BCrypt mechanism, we never store repeated information
        return passwordEncoder.encode(rawPassword);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) throws AuthenticationException {
        if (isEnabled()) {
            String cacheKey = cacheEncode(rawPassword);
            return internalMatches(cacheKey, rawPassword, encodedPassword);
        } else {
            return passwordEncoder.matches(rawPassword, encodedPassword);
        }
    }

    Set<String> getOrCreateHashList(String cacheKey) {
        Set<String> result = cache.getIfPresent(cacheKey);
        if (result == null) {
            if (cache.size() >= getMaxKeys()) {
                cache.invalidateAll();
            }
            cache.put(cacheKey, Collections.synchronizedSet(new LinkedHashSet<>()));
        }
        return cache.getIfPresent(cacheKey);
    }

    private boolean internalMatches(String cacheKey, CharSequence rawPassword, String encodedPassword) {
        Set<String> cacheValue = cache.getIfPresent(cacheKey);
        boolean result = false;
        List<String> searchList = (cacheValue != null ? new ArrayList<>(cacheValue) : Collections.emptyList());
        for (String encoded : searchList) {
            if (hashesEquals(encoded, encodedPassword)) {
                return true;
            }
        }
        if (passwordEncoder.matches(rawPassword, encodedPassword)) {
            result = true;
            cacheValue = getOrCreateHashList(cacheKey);
            if (cacheValue != null) {
                //this list should never grow very long.
                //Only if you store multiple versions of the same password more than once
                if (cacheValue.size() >= getMaxEncodedPasswords()) {
                    cacheValue.clear();
                }
                cacheValue.add(encodedPassword);
            }
        }
        return result;
    }


    String cacheEncode(CharSequence rawPassword) {
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

    int getMaxKeys() {
        return maxKeys;
    }

    public void setMaxKeys(int maxKeys) {
        this.maxKeys = maxKeys;
        buildCache();
    }

    int getMaxEncodedPasswords() {
        return maxEncodedPasswords;
    }

    public void setMaxEncodedPasswords(int maxEncodedPasswords) {
        this.maxEncodedPasswords = maxEncodedPasswords;
        buildCache();
    }

    long getNumberOfKeys() {
        return cache.size();
    }

    ConcurrentMap<CharSequence, Set<String>> asMap() {
        return cache.asMap();
    }

    public void setExpiryInSeconds(int expiryInSeconds) {
        this.expiryInSeconds = expiryInSeconds;
        buildCache();
    }

    private void buildCache() {
        cache = CacheBuilder.newBuilder()
                .expireAfterWrite(expiryInSeconds, TimeUnit.SECONDS)
                .build();
    }
}
