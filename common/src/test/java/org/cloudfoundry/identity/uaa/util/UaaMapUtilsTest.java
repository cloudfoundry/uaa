/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.util;

import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;


public class UaaMapUtilsTest {

    @Test
    public void testFlatten() {
        Map<String, Object> top = new HashMap<>();
        Map<String, Object> secondA = new HashMap<>();
        Map<String, Object> secondB = new HashMap<>();
        Map<String, Object> thirdA = new HashMap<>();
        Map<String, Object> thirdB = new HashMap<>();
        Map<String, Object> thirdC = new HashMap<>();
        Map<String, Object> value = new HashMap<>();

        top.put("secondA", secondA);
        top.put("secondB", secondB);

        secondA.put("thirdA", thirdA);
        secondA.put("thirdB", thirdB);

        secondB.put("thirdC", thirdC);
        secondB.put("thirdB", thirdB);

        thirdA.put("keyA", "valueA");
        thirdB.put("keyB", "valueB");
        thirdC.put("keyC", "valueC");
        thirdC.put("value", value);

        Map<String,Object> flat = UaaMapUtils.flatten(top);
        assertSame(value, flat.get("secondB.thirdC.value"));
        assertSame(secondA, flat.get("secondA"));
        assertEquals("valueC", flat.get("secondB.thirdC.keyC"));


    }
}