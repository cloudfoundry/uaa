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
import java.time.Duration;
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

    private final int ITERATIONS = 25;
    private final int MAX_KEYS = 1000;
    private final int MAX_ENCODED_PASSWORDS = 5;
    private final Duration CACHE_TTL = Duration.ofMinutes(5L);

    private volatile Cache<CharSequence, Set<String>> cache = null;

    private final PasswordEncoder passwordEncoder;

    CachingPasswordEncoder(final PasswordEncoder passwordEncoder) throws NoSuchAlgorithmException {
        this.passwordEncoder = passwordEncoder;
        this.messageDigest = MessageDigest.getInstance("SHA-256");
        this.secret = Utf8.encode(new RandomValueStringGenerator().generate());
        this.salt = KeyGenerators.secureRandom().generateKey();
        buildCache();
    }

    @Override
    public String encode(CharSequence rawPassword) throws AuthenticationException {
        // we always use the BCrypt mechanism, we never store repeated information
        return passwordEncoder.encode(rawPassword);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) throws AuthenticationException {
        String cacheKey = cacheEncode(rawPassword);
        return internalMatches(cacheKey, rawPassword, encodedPassword);
    }

    // internal helpers

    Set<String> getOrCreateHashList(String cacheKey) {
        Set<String> result = cache.getIfPresent(cacheKey);
        if (result == null) {
            if (cache.size() >= MAX_KEYS) {
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
                if (cacheValue.size() >= MAX_ENCODED_PASSWORDS) {
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
            for (int i = 0; i < ITERATIONS; i++) {
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
        return MAX_KEYS;
    }

    int getMaxEncodedPasswords() {
        return MAX_ENCODED_PASSWORDS;
    }

    long getNumberOfKeys() {
        return cache.size();
    }

    ConcurrentMap<CharSequence, Set<String>> asMap() {
        return cache.asMap();
    }

    void buildCache() {
        cache = CacheBuilder.newBuilder()
                .expireAfterWrite(CACHE_TTL.getSeconds(), TimeUnit.SECONDS)
                .build();
    }
}
