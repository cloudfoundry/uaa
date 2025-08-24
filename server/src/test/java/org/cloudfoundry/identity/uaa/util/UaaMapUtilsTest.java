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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.prettyPrintYaml;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.redactValues;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.sortByKeys;

class UaaMapUtilsTest {

    private Map<String, Object> top;
    private Map<String, Object> secondA;
    private Map<String, Object> secondB;
    private Map<String, Object> thirdA;
    private Map<String, Object> thirdB;
    private Map<String, Object> thirdC;
    private Map<String, Object> emptyMap;

    @BeforeEach
    void setup() {
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
    void flatten() {
        Map<String, Object> flat = UaaMapUtils.flatten(top);
        assertThat(flat.get("secondB.thirdC.emptyMap")).isSameAs(emptyMap);
        assertThat(flat.get("secondA")).isSameAs(secondA);
        assertThat(flat).containsEntry("secondB.thirdC.keyC", "valueC");
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
    void sort_nested_map() {
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
        assertThat(visit_all_keys(top)).isNotEqualTo(expectedOrder);
        assertThat(visit_all_keys(sortByKeys(top))).isEqualTo(expectedOrder);
    }

    @Test
    void print_sorted_yaml() {
        String expected = """
                ---
                secondA:
                  thirdA:
                    keyA: valueA
                  thirdB:
                    keyB: valueB
                secondB:
                  thirdB:
                    keyB: valueB
                  thirdC:
                    emptyMap: {
                      }
                    emptyString: ''
                    keyC: valueC
                    nullValue: null
                """;
        assertThat(prettyPrintYaml(top)).isEqualTo(expected);
    }

    @Test
    void hideConfigValues() {
        String expected = """
                ---
                secondA:
                  thirdA:
                    keyA: <redacted>
                  thirdB:
                    keyB: <redacted>
                secondB:
                  thirdB:
                    keyB: <redacted>
                  thirdC:
                    emptyMap: {
                      }
                    emptyString: ''
                    keyC: <redacted>
                    nullValue: null
                """;
        assertThat(prettyPrintYaml(redactValues(top))).isEqualTo(expected);
    }

    private void checkRedacted(Map<String, ?> map) {
        for (String key : map.keySet()) {
            Object value = map.get(key);
            if (value instanceof Map map1) {
                checkRedacted(map1);
            } else {
                assertThat(value).isEqualTo("<redacted>");
            }
        }
    }
}
