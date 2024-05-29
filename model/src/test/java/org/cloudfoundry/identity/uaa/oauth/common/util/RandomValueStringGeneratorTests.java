package org.cloudfoundry.identity.uaa.oauth.common.util;

import org.junit.Before;
import org.junit.Test;

import java.security.SecureRandom;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class RandomValueStringGeneratorTests {

    private RandomValueStringGenerator generator;

    @Before
    public void setup() {
        generator = new RandomValueStringGenerator();
    }

    @Test
    public void generate() {
        String value = generator.generate();
        assertNotNull(value);
        assertEquals("Authorization code is not correct size", 6, value.length());
    }

    @Test
    public void generate_LargeLengthOnConstructor() {
        generator = new RandomValueStringGenerator(1024);
        String value = generator.generate();
        assertNotNull(value);
        assertEquals("Authorization code is not correct size", 1024, value.length());
    }

    @Test
    public void getAuthorizationCodeString() {
        byte[] bytes = new byte[10];
        new SecureRandom().nextBytes(bytes);
        String value = generator.getAuthorizationCodeString(bytes);
        assertNotNull(value);
        assertEquals("Authorization code is not correct size", 10, value.length());
    }

    @Test
    public void setLength() {
        generator.setLength(12);
        String value = generator.generate();
        assertEquals("Authorization code is not correct size", 12, value.length());
    }

    @Test(expected = IllegalArgumentException.class)
    public void setLength_NonPositiveNumber() {
        generator.setLength(-1);
        generator.generate();
    }

    @Test
    public void setRandom() {
        generator.setRandom(new SecureRandom());
        generator.setLength(12);
        String value = generator.generate();
        assertEquals("Authorization code is not correct size", 12, value.length());
    }

    @Test
    public void setCodec() {
        generator = new RandomValueStringGenerator("0123456789".toCharArray());
        String value = generator.generate();
        assertFalse(value.contains("A"));
    }
}