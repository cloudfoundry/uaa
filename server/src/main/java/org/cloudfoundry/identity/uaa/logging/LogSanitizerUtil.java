package org.cloudfoundry.identity.uaa.logging;

public class LogSanitizerUtil {

    public static final String SANITIZED_FLAG = "[SANITIZED]";

    public static String sanitize(String original) {
        String cleaned = original.replace("\r","|")
                .replace("\n","|")
                .replace("\t","|");

        if (!cleaned.equals(original)) {
            cleaned += SANITIZED_FLAG;
        }

        return cleaned;
    }


}
