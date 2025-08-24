package org.cloudfoundry.identity.uaa.util;

import java.awt.*;

public final class ColorHash {

    private ColorHash() {
    }

    public static Color getColor(String input) {
        int hashCode = input.hashCode();
        if (hashCode < 0) {
            hashCode *= -1;
        }
        int r = 20 + 8 * (int) ((1999L * (long) hashCode) % 26);
        int g = 20 + 8 * (int) ((1997L * (long) hashCode) % 26);
        int b = 20 + 8 * (int) ((2003L * (long) hashCode) % 26);
        return new Color(r, g, b);
    }

}
