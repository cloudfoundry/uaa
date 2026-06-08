package org.cloudfoundry.identity.uaa.metrics;


import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class StatusCodeGroupTest {


    @Test
    void getName() {
        StatusCodeGroup group = StatusCodeGroup.valueOf(404);
        assertThat(group.getName()).isEqualTo("4xx");
    }

    @Test
    void throwsWhenInvalid() {
        IllegalArgumentException exception = assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> StatusCodeGroup.valueOf("INVALID GROUP")).actual();
        assertThat(exception.getMessage()).startsWith("No enum constant org.cloudfoundry.identity.uaa.metrics.StatusCodeGroup.INVALID GROUP");

        exception = assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> StatusCodeGroup.valueOf(606)).actual();
        assertThat(exception.getMessage()).startsWith("No matching constant for [" + 606 + "]");
    }
}