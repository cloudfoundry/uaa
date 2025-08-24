package org.cloudfoundry.identity.uaa.metrics;


import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class StatusCodeGroupTest {


    @Test
    void getName() {
        StatusCodeGroup group = StatusCodeGroup.valueOf(404);
        assertThat(group.getName()).isEqualTo("4xx");
    }

    @Test
    void throwsWhenInvalid() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> StatusCodeGroup.valueOf("INVALID GROUP")
        );
        assertThat(exception.getMessage()).startsWith("No enum constant org.cloudfoundry.identity.uaa.metrics.StatusCodeGroup.INVALID GROUP");

        exception = assertThrows(IllegalArgumentException.class,
                () -> StatusCodeGroup.valueOf(606)
        );
        assertThat(exception.getMessage()).startsWith("No matching constant for [" + 606 + "]");
    }
}