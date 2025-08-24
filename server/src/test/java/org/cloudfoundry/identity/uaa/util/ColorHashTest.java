package org.cloudfoundry.identity.uaa.util;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.util.ColorHash.getColor;

class ColorHashTest {
    @Test
    void getColorResultIsConsistent() {
        String input1 = "cat";
        String input2 = "dog";

        assertThat(getColor(input1)).isEqualTo(getColor(input1));
        assertThat(getColor(input2)).isEqualTo(getColor(input2));

        assertThat(getColor(input2)).isNotEqualTo(getColor(input1));
    }
}