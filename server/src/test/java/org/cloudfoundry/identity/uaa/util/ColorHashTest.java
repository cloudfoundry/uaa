package org.cloudfoundry.identity.uaa.util;

import org.junit.Test;

import static org.cloudfoundry.identity.uaa.util.ColorHash.getColor;
import static org.junit.Assert.*;

public class ColorHashTest {
    @Test
    public void getColorResultIsConsistent() {
        String input1 = "cat";
        String input2 = "dog";

        assertEquals(getColor(input1), getColor(input1));
        assertEquals(getColor(input2), getColor(input2));

        assertNotEquals(getColor(input1), getColor(input2));
    }
}