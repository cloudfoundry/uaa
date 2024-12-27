package org.cloudfoundry.identity.uaa.logging;

import org.springframework.lang.Nullable;

public final class LogSanitizerUtil {

    public static final String SANITIZED_FLAG = "[SANITIZED]";

    private LogSanitizerUtil() {
    }

    @Nullable
    public static String sanitize(String original) {
        if (original == null) {
            return null;
        }

        String cleaned = original.replace("\r", "|")
                .replace("\n", "|")
                .replace("\t", "|");

        if (!cleaned.equals(original)) {
            cleaned += SANITIZED_FLAG;
        }

        return cleaned;
    }

}
