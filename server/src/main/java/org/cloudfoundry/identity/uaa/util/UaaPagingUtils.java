/*
 * *****************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.util;

import java.util.Collections;
import java.util.List;

public class UaaPagingUtils {

    /**
     * Calculates the substring of a list based on a 1 based start index never
     * exceeding
     * the bounds of the list.
     * 
     * @param input
     * @param startIndex
     * @param count
     * @return
     */
    public static <T> List<T> subList(List<T> input, int startIndex, int count) {
        int fromIndex = startIndex - 1;
        int toIndex = fromIndex + count;
        if (toIndex >= input.size()) {
            toIndex = input.size();
        }
        if (fromIndex >= toIndex) {
            return Collections.emptyList();
        }
        return input.subList(fromIndex, toIndex);
    }
}
