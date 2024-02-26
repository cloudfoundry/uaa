package org.cloudfoundry.identity.uaa.logging;

import javax.annotation.Nullable;

public class LogSanitizerUtil {

    public static final String SANITIZED_FLAG = "[SANITIZED]";

    @Nullable
    public static String sanitize(String original) {
        if (original == null) return original;

        String cleaned = original.replace("\r","|")
                .replace("\n","|")
                .replace("\t","|");

        if (!cleaned.equals(original)) {
            cleaned += SANITIZED_FLAG;
        }

        return cleaned;
    }

}
