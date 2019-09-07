package org.cloudfoundry.identity.uaa.util;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import java.util.concurrent.ConcurrentMap;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.lessThan;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CachingPasswordEncoderTest {

    private PasswordEncoder passwordEncoder;
    private CachingPasswordEncoder cachingPasswordEncoder;
    private String password;

    @BeforeEach
    void setUp() throws Exception {
        passwordEncoder = new BCryptPasswordEncoder(4); // 4 mean as fast/weak as possible
        cachingPasswordEncoder = new CachingPasswordEncoder(passwordEncoder);
        password = new RandomValueStringGenerator().generate();
    }

    @Test
    void encode() {
        String encode1 = cachingPasswordEncoder.encode(password);
        String encode2 = passwordEncoder.encode(password);
        assertNotEquals(encode1, encode2);
        assertTrue(passwordEncoder.matches(password, encode1));
        assertTrue(passwordEncoder.matches(password, encode2));
        assertTrue(cachingPasswordEncoder.matches(password, encode1));
        assertTrue(cachingPasswordEncoder.matches(password, encode2));
    }

    @Test
    void matches() {
        cachingPasswordEncoder.encode(password);
        String encoded = cachingPasswordEncoder.encode(password);
        int iterations = 5;
        for (int i = 0; i < iterations; i++) {
            assertTrue(passwordEncoder.matches(password, encoded));
            assertTrue(cachingPasswordEncoder.matches(password, encoded));
        }
    }

    @Test
    void matchesButExpires() throws Exception {
        Duration shortTTL = Duration.ofSeconds(1);
        ReflectionTestUtils.setField(cachingPasswordEncoder, "CACHE_TTL", shortTTL);
        cachingPasswordEncoder.buildCache();
        String encoded = cachingPasswordEncoder.encode(password);
        String cacheKey = cachingPasswordEncoder.cacheEncode(password);

        assertTrue(passwordEncoder.matches(password, encoded));
        assertTrue(cachingPasswordEncoder.matches(password, encoded));

        assertTrue(cachingPasswordEncoder.getOrCreateHashList(cacheKey).size() > 0,
                "Password is no longer cached when we expected it to be cached");

        Thread.sleep(shortTTL.toMillis() + 100);

        assertEquals(0, cachingPasswordEncoder.getOrCreateHashList(cacheKey).size(), "Password is still cached when we expected it to be expired");
    }

    @Test
    void notMatches() {
        cachingPasswordEncoder.encode(password);
        String encoded = cachingPasswordEncoder.encode(password);
        password = new RandomValueStringGenerator().generate();
        int iterations = 5;
        for (int i = 0; i < iterations; i++) {
            assertFalse(passwordEncoder.matches(password, encoded));
            assertFalse(cachingPasswordEncoder.matches(password, encoded));
        }
    }

    @Test
    void cacheIs10XFasterThanNonCached() throws NoSuchAlgorithmException {
        passwordEncoder = new BCryptPasswordEncoder();
        cachingPasswordEncoder = new CachingPasswordEncoder(passwordEncoder);

        int iterations = 10;

        String password = new RandomValueStringGenerator().generate();
        String encodedBCrypt = cachingPasswordEncoder.encode(password);
        PasswordEncoder nonCachingPasswordEncoder = passwordEncoder;

        assertTrue(cachingPasswordEncoder.matches(password, encodedBCrypt)); // warm the cache

        Instant start = Instant.now();
        for (int i = 0; i < iterations; i++) {
            assertTrue(nonCachingPasswordEncoder.matches(password, encodedBCrypt));
        }
        Instant middle = Instant.now();
        for (int i = 0; i < iterations; i++) {
            assertTrue(cachingPasswordEncoder.matches(password, encodedBCrypt));
        }
        Instant end = Instant.now();

        Duration bCryptTime = Duration.between(start, middle);
        Duration cacheTime = Duration.between(middle, end);

        assertThat(
                "cache wasn't fast enough (see ISO-8601 for understanding the strings)",
                cacheTime.multipliedBy(10L),
                is(lessThan(bCryptTime))
        );
    }

    @Test
    // TODO: This test takes a long time to run :(
    void ensureNoMemoryLeak() {
        assertEquals(0, cachingPasswordEncoder.getNumberOfKeys());
        for (int i = 0; i < cachingPasswordEncoder.getMaxKeys(); i++) {
            String password = new RandomValueStringGenerator().generate();
            for (int j = 0; j < cachingPasswordEncoder.getMaxEncodedPasswords(); j++) {
                String encoded = cachingPasswordEncoder.encode(password);
                assertTrue(cachingPasswordEncoder.matches(password, encoded));
            }
        }
        assertEquals(cachingPasswordEncoder.getMaxKeys(), cachingPasswordEncoder.getNumberOfKeys());
        String password = new RandomValueStringGenerator().generate();
        String encoded = cachingPasswordEncoder.encode(password);
        assertTrue(cachingPasswordEncoder.matches(password, encoded));
        //overflow happened
        assertEquals(1, cachingPasswordEncoder.getNumberOfKeys());


        for (int j = 1; j < cachingPasswordEncoder.getMaxEncodedPasswords(); j++) {
            encoded = cachingPasswordEncoder.encode(password);
            assertTrue(cachingPasswordEncoder.matches(password, encoded));
        }

        ConcurrentMap<CharSequence, Set<String>> cache = cachingPasswordEncoder.asMap();
        assertNotNull(cache);
        Set<String> passwords = cache.get(cachingPasswordEncoder.cacheEncode(password));
        assertNotNull(passwords);
        assertEquals(cachingPasswordEncoder.getMaxEncodedPasswords(), passwords.size());
        cachingPasswordEncoder.matches(password, cachingPasswordEncoder.encode(password));
        assertEquals(1, passwords.size());
    }
}
