package org.cloudfoundry.identity.uaa.oauth.common.util;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class RandomValueStringGeneratorTests {

    private RandomValueStringGenerator generator;

    @BeforeEach
    void setup() {
        generator = new RandomValueStringGenerator();
    }

    @Test
    void generate() {
        String value = generator.generate();
        assertThat(value).as("Authorization code is not correct size").hasSize(6);
    }

    @Test
    void generate_LargeLengthOnConstructor() {
        generator = new RandomValueStringGenerator(1024);
        String value = generator.generate();
        assertThat(value).as("Authorization code is not correct size").hasSize(1024);
    }

    @Test
    void getAuthorizationCodeString() {
        byte[] bytes = new byte[10];
        new SecureRandom().nextBytes(bytes);
        String value = generator.getAuthorizationCodeString(bytes);
        assertThat(value).as("Authorization code is not correct size").hasSize(10);
    }

    @Test
    void setLength() {
        generator.setLength(12);
        String value = generator.generate();
        assertThat(value).as("Authorization code is not correct size").hasSize(12);
    }

    @Test
    void setLength_NonPositiveNumber() {
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() ->
                generator.setLength(-1));
    }

    @Test
    void setRandom() {
        generator.setRandom(new SecureRandom());
        generator.setLength(12);
        String value = generator.generate();
        assertThat(value).as("Authorization code is not correct size").hasSize(12);
    }

    @Test
    void setCodec() {
        generator = new RandomValueStringGenerator("0123456789".toCharArray());
        String value = generator.generate();
        assertThat(value).doesNotContain("A");
    }
}
