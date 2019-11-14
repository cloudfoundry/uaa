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

import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.prettyPrintYaml;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.redactValues;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.sortByKeys;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertSame;


public class UaaMapUtilsTest {

    private Map<String, Object> top;
    private Map<String, Object> secondA;
    private Map<String, Object> secondB;
    private Map<String, Object> thirdA;
    private Map<String, Object> thirdB;
    private Map<String, Object> thirdC;
    private Map<String, Object> emptyMap;

    @Before
    public void setup() {
        top = new HashMap<>();
        secondA = new HashMap<>();
        secondB = new HashMap<>();
        thirdA = new HashMap<>();
        thirdB = new HashMap<>();
        thirdC = new HashMap<>();
        emptyMap = new HashMap<>();

        top.put("secondB", secondB);
        top.put("secondA", secondA);

        secondA.put("thirdA", thirdA);
        secondA.put("thirdB", thirdB);

        secondB.put("thirdC", thirdC);
        secondB.put("thirdB", thirdB);

        thirdC.put("keyC", "valueC");
        thirdB.put("keyB", "valueB");
        thirdA.put("keyA", "valueA");
        thirdC.put("emptyMap", emptyMap);
        thirdC.put("emptyString", "");
        thirdC.put("nullValue", null);
    }

    @Test
    public void testFlatten() {
        Map<String,Object> flat = UaaMapUtils.flatten(top);
        assertSame(emptyMap, flat.get("secondB.thirdC.emptyMap"));
        assertSame(secondA, flat.get("secondA"));
        assertEquals("valueC", flat.get("secondB.thirdC.keyC"));
    }

    public void internal_visit_all_keys(Map<String, Object> map, List<String> keys) {
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            keys.add(entry.getKey());
            if (entry.getValue() instanceof Map) {
                internal_visit_all_keys((Map<String, Object>) entry.getValue(), keys);
            }
        }
    }

    public List<String> visit_all_keys(Map<String, Object> map) {
        List<String> result = new LinkedList<>();
        internal_visit_all_keys(map, result);
        return result;
    }

    @Test
    public void sort_nested_map() {
        List<String> expectedOrder = Arrays.asList(
            "secondA",
            "thirdA",
            "keyA",
            "thirdB",
            "keyB",
            "secondB",
            "thirdB",
            "keyB",
            "thirdC",
            "emptyMap",
            "emptyString",
            "keyC",
            "nullValue"
        );
        assertNotEquals(expectedOrder, visit_all_keys(top));
        assertEquals(expectedOrder, visit_all_keys(sortByKeys(top)));
    }

    @Test
    public void print_sorted_yaml() {
        String expected = "---\n" +
            "secondA:\n" +
            "  thirdA:\n" +
            "    keyA: valueA\n" +
            "  thirdB:\n" +
            "    keyB: valueB\n" +
            "secondB:\n" +
            "  thirdB:\n" +
            "    keyB: valueB\n" +
            "  thirdC:\n" +
            "    emptyMap: {\n" +
            "      }\n" +
            "    emptyString: ''\n" +
            "    keyC: valueC\n" +
            "    nullValue: null\n";
        assertEquals(expected, prettyPrintYaml(top));
    }

    @Test
    public void testHideConfigValues() {
        String expected = "---\n" +
            "secondA:\n" +
            "  thirdA:\n" +
            "    keyA: <redacted>\n" +
            "  thirdB:\n" +
            "    keyB: <redacted>\n" +
            "secondB:\n" +
            "  thirdB:\n" +
            "    keyB: <redacted>\n" +
            "  thirdC:\n" +
            "    emptyMap: {\n" +
            "      }\n" +
            "    emptyString: ''\n" +
            "    keyC: <redacted>\n" +
            "    nullValue: null\n";
        assertEquals(expected, prettyPrintYaml(redactValues(top)));
    }

    private void checkRedacted(Map<String,?> map) {
        for (String key : map.keySet()) {
            Object value = map.get(key);
            if (value instanceof Map) {
                checkRedacted((Map)value);
            } else  {
                assertEquals("<redacted>", value);
            }
        }
    }

}