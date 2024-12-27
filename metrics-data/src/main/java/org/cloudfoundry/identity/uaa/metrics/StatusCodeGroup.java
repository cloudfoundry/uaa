/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.metrics;

public enum StatusCodeGroup {
    INFORMATIONAL("1xx", 1),
    SUCCESS("2xx", 2),
    REDIRECT("3xx", 3),
    CLIENT_ERROR("4xx", 4),
    SERVER_ERROR("5xx", 5);

    private final String name;
    private final int value;

    StatusCodeGroup(String name, int value) {
        this.name = name;
        this.value = value;
    }

    public String getName() {
        return name;
    }

    public static StatusCodeGroup valueOf(int statusCode) {
        int seriesCode = statusCode / 100;
        for (StatusCodeGroup series : values()) {
            if (series.value == seriesCode) {
                return series;
            }
        }
        throw new IllegalArgumentException("No matching constant for [" + statusCode + "]");
    }
}
