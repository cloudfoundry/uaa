package org.cloudfoundry.identity.uaa.logging;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class LogSanitizerUtilTest {

    @Test
    void sanitizeInput() {
        assertThat(LogSanitizerUtil.sanitize("one\ntwo\tthree\rfour")).isEqualTo("one|two|three|four[SANITIZED]");
    }

    @Test
    void sanitizeCleanInput() {
        assertThat(LogSanitizerUtil.sanitize("one two three four")).isEqualTo("one two three four");
    }

    @Test
    void sanitizeNull() {
        assertThat(LogSanitizerUtil.sanitize(null)).isNull();
    }
}