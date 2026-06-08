package org.cloudfoundry.identity.uaa.ratelimiting.util;

import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class IntUtilsTest {

    @Test
    void parsing() {
        assertThat(IntUtils.parse("1", null)).isOne();
        assertThat(IntUtils.parseNoException("1", null)).isOne();
        assertThat(IntUtils.parse(" ", -1)).isEqualTo(-1);
        assertThat(IntUtils.parseNoException(" ", -1)).isEqualTo(-1);
        assertThat(IntUtils.parse(null, -2)).isEqualTo(-2);
        assertThat(IntUtils.parseNoException(null, -2)).isEqualTo(-2);

        assertThatThrownBy(() -> IntUtils.parse("!Number", -1)).asInstanceOf(InstanceOfAssertFactories.throwable(NumberFormatException.class));
        assertThat(IntUtils.parseNoException("!Number", -1)).isEqualTo(-1);
    }
}