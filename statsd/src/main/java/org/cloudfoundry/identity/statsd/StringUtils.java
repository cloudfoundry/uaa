package org.cloudfoundry.identity.statsd;


public class StringUtils {

    /**
     * Convert a string from camel case to underscores, also replacing periods with underscores (so for example a fully
     * qualified Java class name gets underscores everywhere).
     *
     * @param value a camel case String
     * @return the same value with camels converted to underscores
     */
    public static String camelToUnderscore(String value) {
        return camelToDelimiter(value, "_");
    }

    public static String camelToDelimiter(String value, String delimiter) {
        String result = value.replace(" ", delimiter);
        result = result.replaceAll("([a-z])([A-Z])", "$1" + delimiter + "$2");
        result = result.replace(".", delimiter);
        result = result.toLowerCase();
        return result;
    }

    public static String camelToPeriod(String value) {
        return camelToDelimiter(value, "_");
    }
}
