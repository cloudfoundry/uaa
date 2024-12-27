package org.cloudfoundry.identity.uaa.ratelimiting.util;

import org.apache.commons.lang3.StringUtils;

public final class IntUtils {

    private IntUtils() {
    }

    public static Integer parseNoException(String source, Integer defaultOnEmpty) {
        try {
            return parse(source, defaultOnEmpty);
        }
        catch (NumberFormatException e) {
            return defaultOnEmpty;
        }
    }

    public static Integer parse(String source, Integer defaultOnEmpty) {
        source = StringUtils.stripToEmpty(source);
        return source.isEmpty() ? defaultOnEmpty : Integer.valueOf(Integer.parseInt(source));
    }
}
