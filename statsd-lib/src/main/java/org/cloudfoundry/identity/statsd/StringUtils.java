/*
 * *****************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 * <p/>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p/>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/

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
