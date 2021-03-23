package org.cloudfoundry.identity.uaa.util;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasLength;
import static org.junit.jupiter.api.Assertions.assertThrows;

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
        assertThat(uaaRandomStringUtil.getSecureRandom(length), hasLength(length));
    }

    @Test
    void invalidLength() {
        assertThrows(IllegalArgumentException.class, () -> uaaRandomStringUtil.getSecureRandom(-1));
    }

}
