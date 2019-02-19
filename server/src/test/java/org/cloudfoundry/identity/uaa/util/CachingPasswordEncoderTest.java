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

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import java.util.Timer;
import java.util.concurrent.ConcurrentMap;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertFalse;
import static junit.framework.Assert.assertNotNull;
import static junit.framework.Assert.assertSame;
import static junit.framework.Assert.assertTrue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.lessThan;

public class CachingPasswordEncoderTest  {

    private CachingPasswordEncoder cachingPasswordEncoder;
    private String password;

    @Before
    public void setUp() throws Exception {
        cachingPasswordEncoder = new CachingPasswordEncoder();
        cachingPasswordEncoder.setPasswordEncoder(new BCryptPasswordEncoder());
        password = new RandomValueStringGenerator().generate();
    }

    @Test
    public void testSetPasswordEncoder() throws Exception {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        cachingPasswordEncoder.setPasswordEncoder(encoder);
        assertSame(encoder, cachingPasswordEncoder.getPasswordEncoder());
    }


    @Test
    public void testEncode() throws Exception {
        String encode1 = cachingPasswordEncoder.encode(password);
        String encode2 = cachingPasswordEncoder.getPasswordEncoder().encode(password);
        assertFalse(encode1.equals(encode2));
        assertTrue(cachingPasswordEncoder.getPasswordEncoder().matches(password, encode1));
        assertTrue(cachingPasswordEncoder.getPasswordEncoder().matches(password, encode2));
        assertTrue(cachingPasswordEncoder.matches(password, encode1));
        assertTrue(cachingPasswordEncoder.matches(password, encode2));
    }

    @Test
    public void testMatches() throws Exception {
        cachingPasswordEncoder.encode(password);
        String encoded = cachingPasswordEncoder.encode(password);
        int iterations = 5;
        for (int i=0; i<iterations; i++) {
            assertTrue(cachingPasswordEncoder.getPasswordEncoder().matches(password, encoded));
            assertTrue(cachingPasswordEncoder.matches(password, encoded));
        }
    }

    @Test
    public void testMatches_But_Expires() throws Exception {
        cachingPasswordEncoder.setExpiryInSeconds(5);
        cachingPasswordEncoder.encode(password);
        String cacheKey = cachingPasswordEncoder.cacheEncode(password);
        String encoded = cachingPasswordEncoder.encode(password);
        int iterations = 5;
        for (int i=0; i<iterations; i++) {
            assertTrue(cachingPasswordEncoder.getPasswordEncoder().matches(password, encoded));
            assertTrue(cachingPasswordEncoder.matches(password, encoded));
            assertTrue(cachingPasswordEncoder.getOrCreateHashList(cacheKey).size()>0);
        }
        Thread.sleep(5500);
        assertTrue(cachingPasswordEncoder.getOrCreateHashList(cacheKey).size()==0);
    }

    @Test
    public void testNotMatches() throws Exception {
        cachingPasswordEncoder.encode(password);
        String encoded = cachingPasswordEncoder.encode(password);
        password = new RandomValueStringGenerator().generate();
        int iterations = 5;
        for (int i=0; i<iterations; i++) {
            assertFalse(cachingPasswordEncoder.getPasswordEncoder().matches(password, encoded));
            assertFalse(cachingPasswordEncoder.matches(password, encoded));
        }
    }

    @Test
    public void cacheIs10XFasterThanNonCached() {
        int iterations = 10;

        String password = new RandomValueStringGenerator().generate();
        String encodedBcrypt = cachingPasswordEncoder.encode(password);
        PasswordEncoder nonCachingPasswordEncoder = cachingPasswordEncoder.getPasswordEncoder();

        assertTrue(cachingPasswordEncoder.matches(password, encodedBcrypt)); // warm the cache

        Instant start = Instant.now();
        for (int i = 0; i < iterations; i++) {
            assertTrue(nonCachingPasswordEncoder.matches(password, encodedBcrypt));
        }
        Instant middle = Instant.now();
        for (int i = 0; i < iterations; i++) {
            assertTrue(cachingPasswordEncoder.matches(password, encodedBcrypt));
        }
        Instant end = Instant.now();

        Duration bcryptTime = Duration.between(start, middle);
        Duration cacheTime = Duration.between(middle, end);

        assertThat(
                "cache wasn't fast enough (see ISO-8601 for understanding the strings)",
                cacheTime.multipliedBy(10L),
                is(lessThan(bcryptTime))
        );
    }

    @Test
    public void testEnsureNoMemoryLeak() {
        int maxkeys = 10;
        int maxpasswords = 4;
        cachingPasswordEncoder.setMaxKeys(maxkeys);
        assertEquals(maxkeys, cachingPasswordEncoder.getMaxKeys());
        cachingPasswordEncoder.setMaxEncodedPasswords(4);
        assertEquals(maxpasswords, cachingPasswordEncoder.getMaxEncodedPasswords());
        assertEquals(0, cachingPasswordEncoder.getNumberOfKeys());
        for (int i=0; i<cachingPasswordEncoder.getMaxKeys(); i++) {
            String password = new RandomValueStringGenerator().generate();
            for (int j=0; j<cachingPasswordEncoder.getMaxEncodedPasswords(); j++) {
                String encoded = cachingPasswordEncoder.encode(password);
                assertTrue(cachingPasswordEncoder.matches(password, encoded));
            }
        }
        assertEquals(maxkeys, cachingPasswordEncoder.getNumberOfKeys());
        String password = new RandomValueStringGenerator().generate();
        String encoded = cachingPasswordEncoder.encode(password);
        assertTrue(cachingPasswordEncoder.matches(password, encoded));
        //overflow happened
        assertEquals(1, cachingPasswordEncoder.getNumberOfKeys());


        for (int j=1; j<cachingPasswordEncoder.getMaxEncodedPasswords(); j++) {
            encoded = cachingPasswordEncoder.encode(password);
            assertTrue(cachingPasswordEncoder.matches(password, encoded));
        }

        ConcurrentMap<CharSequence, Set<String>> cache = cachingPasswordEncoder.asMap();
        assertNotNull(cache);
        Set<String> passwords = cache.get(cachingPasswordEncoder.cacheEncode(password));
        assertNotNull(passwords);
        assertEquals(maxpasswords, passwords.size());
        cachingPasswordEncoder.matches(password, cachingPasswordEncoder.encode(password));
        assertEquals(1, passwords.size());
    }


    @Test
    public void testDisabledMatchesSpeedTest() throws Exception {
        int iterations = 15;
        cachingPasswordEncoder.setEnabled(false);
        assertFalse(cachingPasswordEncoder.isEnabled());

        String password = new RandomValueStringGenerator().generate();
        String encodedBcrypt = cachingPasswordEncoder.encode(password);
        long nanoStart = System.nanoTime();
        for (int i=0; i<iterations; i++) {
            assertTrue(cachingPasswordEncoder.getPasswordEncoder().matches(password, encodedBcrypt));
        }
        long nanoStop = System.nanoTime();
        long bcryptTime = nanoStop - nanoStart;
        nanoStart = System.nanoTime();
        for (int i=0; i<iterations; i++) {
            assertTrue(cachingPasswordEncoder.matches(password, encodedBcrypt));
        }
        nanoStop = System.nanoTime();
        long cacheTime = nanoStop - nanoStart;
        //assert that the cache is at least 10 times faster
        assertFalse(bcryptTime > (10 * cacheTime));
        assertEquals(0, cachingPasswordEncoder.getNumberOfKeys());
    }
}
