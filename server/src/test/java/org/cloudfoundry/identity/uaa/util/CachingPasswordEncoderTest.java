package org.cloudfoundry.identity.uaa.util;

import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import java.util.concurrent.ConcurrentMap;

import static org.assertj.core.api.Assertions.assertThat;

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
        assertThat(encode2).isNotEqualTo(encode1);
        assertThat(passwordEncoder.matches(password, encode1)).isTrue();
        assertThat(passwordEncoder.matches(password, encode2)).isTrue();
        assertThat(cachingPasswordEncoder.matches(password, encode1)).isTrue();
        assertThat(cachingPasswordEncoder.matches(password, encode2)).isTrue();
    }

    @Test
    void matches() {
        cachingPasswordEncoder.encode(password);
        String encoded = cachingPasswordEncoder.encode(password);
        int iterations = 5;
        for (int i = 0; i < iterations; i++) {
            assertThat(passwordEncoder.matches(password, encoded)).isTrue();
            assertThat(cachingPasswordEncoder.matches(password, encoded)).isTrue();
        }
    }

    @Test
    void matchesButExpires() throws Exception {
        Duration shortTTL = Duration.ofSeconds(1);
        synchronized (CachingPasswordEncoder.class) {
            CachingPasswordEncoder.DEFAULT_CACHE_TTL = shortTTL;
            cachingPasswordEncoder = new CachingPasswordEncoder(passwordEncoder);
            CachingPasswordEncoder.DEFAULT_CACHE_TTL = Duration.ofMinutes(5);
        }
        String encoded = cachingPasswordEncoder.encode(password);
        String cacheKey = cachingPasswordEncoder.cacheEncode(password);

        assertThat(passwordEncoder.matches(password, encoded)).isTrue();
        assertThat(cachingPasswordEncoder.matches(password, encoded)).isTrue();
        assertThat(cachingPasswordEncoder.getOrCreateHashList(cacheKey)).as("Password is no longer cached when we expected it to be cached").isNotEmpty();

        Thread.sleep(shortTTL.toMillis() + 100);
        assertThat(cachingPasswordEncoder.getOrCreateHashList(cacheKey)).as("Password is still cached when we expected it to be expired").isEmpty();
    }

    @Test
    void notMatches() {
        cachingPasswordEncoder.encode(password);
        String encoded = cachingPasswordEncoder.encode(password);
        password = new RandomValueStringGenerator().generate();
        int iterations = 5;
        for (int i = 0; i < iterations; i++) {
            assertThat(passwordEncoder.matches(password, encoded)).isFalse();
            assertThat(cachingPasswordEncoder.matches(password, encoded)).isFalse();
        }
    }

    @Test
    void cacheIs10XFasterThanNonCached() throws NoSuchAlgorithmException {
        passwordEncoder = new BCryptPasswordEncoder();
        cachingPasswordEncoder = new CachingPasswordEncoder(passwordEncoder);

        int iterations = 10;

        password = new RandomValueStringGenerator().generate();
        String encodedBCrypt = cachingPasswordEncoder.encode(password);
        PasswordEncoder nonCachingPasswordEncoder = passwordEncoder;

        assertThat(cachingPasswordEncoder.matches(password, encodedBCrypt)).isTrue(); // warm the cache

        Instant start = Instant.now();
        for (int i = 0; i < iterations; i++) {
            assertThat(nonCachingPasswordEncoder.matches(password, encodedBCrypt)).isTrue();
        }
        Instant middle = Instant.now();
        for (int i = 0; i < iterations; i++) {
            assertThat(cachingPasswordEncoder.matches(password, encodedBCrypt)).isTrue();
        }
        Instant end = Instant.now();

        Duration bCryptTime = Duration.between(start, middle);
        Duration cacheTime = Duration.between(middle, end);

        assertThat(cacheTime.multipliedBy(10L)).as("cache wasn't fast enough (see ISO-8601 for understanding the strings)").isLessThan(bCryptTime);
    }

    @Test
    void ensureNoMemoryLeak() {
        // TODO: This test takes a long time to run :(
        assertThat(cachingPasswordEncoder.getNumberOfKeys()).isZero();
        for (int i = 0; i < cachingPasswordEncoder.getMaxKeys(); i++) {
            password = new RandomValueStringGenerator().generate();
            for (int j = 0; j < cachingPasswordEncoder.getMaxEncodedPasswords(); j++) {
                String encoded = cachingPasswordEncoder.encode(password);
                assertThat(cachingPasswordEncoder.matches(password, encoded)).isTrue();
            }
        }
        assertThat(cachingPasswordEncoder.getNumberOfKeys()).isEqualTo(cachingPasswordEncoder.getMaxKeys());
        password = new RandomValueStringGenerator().generate();
        String encoded = cachingPasswordEncoder.encode(password);
        assertThat(cachingPasswordEncoder.matches(password, encoded)).isTrue();
        //overflow happened
        assertThat(cachingPasswordEncoder.getNumberOfKeys()).isOne();

        for (int j = 1; j < cachingPasswordEncoder.getMaxEncodedPasswords(); j++) {
            encoded = cachingPasswordEncoder.encode(password);
            assertThat(cachingPasswordEncoder.matches(password, encoded)).isTrue();
        }

        ConcurrentMap<CharSequence, Set<String>> cache = cachingPasswordEncoder.asMap();
        assertThat(cache).isNotNull();
        Set<String> passwords = cache.get(cachingPasswordEncoder.cacheEncode(password));
        assertThat(passwords).hasSize(cachingPasswordEncoder.getMaxEncodedPasswords());
        cachingPasswordEncoder.matches(password, cachingPasswordEncoder.encode(password));
        assertThat(passwords).hasSize(1);
    }
}
