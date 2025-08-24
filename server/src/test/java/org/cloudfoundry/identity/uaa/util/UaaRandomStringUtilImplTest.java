package org.cloudfoundry.identity.uaa.util;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

class UaaRandomStringUtilImplTest {

    private UaaRandomStringUtil uaaRandomStringUtil;

    @BeforeEach
    void setUp() throws NoSuchProviderException, NoSuchAlgorithmException {
        uaaRandomStringUtil = new UaaRandomStringUtilImpl();
    }

    @ParameterizedTest
    @ValueSource(ints = {
            0,
            10,
            100,
    })
    void secureRandom(final int length) {
        assertThat(uaaRandomStringUtil.getSecureRandom(length)).hasSize(length);
    }

    @Test
    void invalidLength() {
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> uaaRandomStringUtil.getSecureRandom(-1));
    }

}
