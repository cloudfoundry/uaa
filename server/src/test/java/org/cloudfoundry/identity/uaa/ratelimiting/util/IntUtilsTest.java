package org.cloudfoundry.identity.uaa.ratelimiting.util;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

class IntUtilsTest {

    @Test
    void parsing() {
        assertThat(IntUtils.parse("1", null)).isOne();
        assertThat(IntUtils.parseNoException("1", null)).isOne();
        assertThat(IntUtils.parse(" ", -1)).isEqualTo(-1);
        assertThat(IntUtils.parseNoException(" ", -1)).isEqualTo(-1);
        assertThat(IntUtils.parse(null, -2)).isEqualTo(-2);
        assertThat(IntUtils.parseNoException(null, -2)).isEqualTo(-2);

        assertThatExceptionOfType(NumberFormatException.class).isThrownBy(() -> IntUtils.parse("!Number", -1));
        assertThat(IntUtils.parseNoException("!Number", -1)).isEqualTo(-1);
    }
}