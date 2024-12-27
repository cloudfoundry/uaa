package org.cloudfoundry.identity.uaa.ratelimiting.util;

import static org.apache.commons.lang3.StringUtils.stripToNull;

import java.util.function.Supplier;

import lombok.RequiredArgsConstructor;

public final class StringUtilities {

    private StringUtilities() {
    }

    public static String toErrorMsg(Exception e) {
        if (e == null) {
            return null;
        }
        String msg = stripToNull(e.getMessage());
        return msg != null ? msg : e.getClass().getSimpleName();
    }

    public static String options(String labelSingularButPluralWithAnS, Object[] validOptions) {
        return options(labelSingularButPluralWithAnS, labelSingularButPluralWithAnS + "s", validOptions);
    }

    public static String options(String labelSingular, String labelPlural, Object[] validOptions) {
        switch (count(validOptions)) {
            case 0:
                return "no " + labelPlural;
            case 1:
                return "the " + labelSingular + " is: " + options(validOptions);
            default:
                return "the " + labelPlural + " are: " + options(validOptions);
        }
    }

    public static String options(Object[] validOptions) {
        return 0 == count(validOptions) ? "" : optionsNotEmpty(validOptions);
    }

    private static int count(Object[] array) {
        return array == null ? 0 : array.length;
    }

    private static String optionsNotEmpty(Object[] validOptions) {
        StringBuilder sb = new StringBuilder();
        if (validOptions.length > 1) {
            for (int i = validOptions.length; --i > 0; ) {
                append(sb, validOptions[i]).append(", ");
            }
            sb.append("or ");
        }
        return append(sb, validOptions[0]).toString();
    }

    private static StringBuilder append(StringBuilder sb, Object value) {
        if (value == null) {
            return sb.append("null");
        }
        boolean wasString = value instanceof String;
        String str = value.toString();
        if (str == null) {
            return sb.append(value.getClass().getSimpleName());
        }
        String wrapper = wasString ? "'" : "";
        return sb.append(wrapper).append(str).append(wrapper);
    }

    /**
     * A String Supplier (proxy with Caching) - NOT Thread Safe!
     */
    @RequiredArgsConstructor
    public static class SupplierWithCaching implements Supplier<String> {
        private final Supplier<String> supplier;
        private String value;
        private boolean populated;

        @Override
        public String get() {
            if (!populated) {
                populated = true;
                value = supplier.get();
            }
            return value;
        }
    }
}
