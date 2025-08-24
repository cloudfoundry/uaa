/*
 * ******************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * ******************************************************************************
 */
package org.cloudfoundry.identity.uaa.util;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.util.MultiValueMap;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Arjen Poutsma
 * @author fhanik
 */
class LinkedMaskingMultiValueMapTests {

    private LinkedMaskingMultiValueMap<String, String> map;
    private LinkedMaskingMultiValueMap<Object, Object> objectMap;

    @BeforeEach
    void setUp() {
        map = new LinkedMaskingMultiValueMap<>("password");
        objectMap = new LinkedMaskingMultiValueMap<>("password");
    }

    @Test
    void add() {
        map.add("key", "value1");
        map.add("key", "value2");
        assertThat(map.size()).isOne();
        List<String> expected = new ArrayList<>(2);
        expected.add("value1");
        expected.add("value2");
        assertThat(map).containsEntry("key", expected);
    }

    @Test
    void addAll() {
        map.add("key", "value1");
        map.addAll("key", Arrays.asList("value2", "value3"));
        assertThat(map.size()).isOne();
        assertThat(map.get("key")).hasSize(3)
                .containsExactly("value1", "value2", "value3");
    }

    @Test
    void addAllFromAnotherMultiValueMap() {
        LinkedMaskingMultiValueMap<String, String> toCopy = new LinkedMaskingMultiValueMap<>();
        toCopy.add("key1", "value1");
        toCopy.add("key2", "value2");
        map.add("key1", "existing value");
        map.addAll(toCopy);
        assertThat(map).hasSize(2);
        assertThat(map.get("key1")).hasSize(2)
                .containsExactly("existing value", "value1");
        assertThat(map.get("key2")).hasSize(1)
                .containsExactly("value2");
    }

    @Test
    void getFirst() {
        List<String> values = new ArrayList<>(2);
        values.add("value1");
        values.add("value2");
        map.put("key", values);
        assertThat(map.getFirst("key")).isEqualTo("value1");
        assertThat(map.getFirst("other")).isNull();
    }

    @Test
    void set() {
        map.set("key", "value1");
        map.set("key", "value2");
        assertThat(map).hasSize(1)
                .containsEntry("key", List.of("value2"));
    }

    @Test
    void equals() {
        map.set("key1", "value1");
        assertThat(map).isEqualTo(map);
        MultiValueMap<String, String> o1 = new LinkedMaskingMultiValueMap<>();
        o1.set("key1", "value1");
        assertThat(o1).isEqualTo(map);
        assertThat(map).isEqualTo(o1);
        Map<String, List<String>> o2 = new HashMap<>();
        o2.put("key1", Collections.singletonList("value1"));
        assertThat(o2).isEqualTo(map);
        assertThat(map).isEqualTo(o2);
    }

    @Test
    void selfReferenceKey() {
        objectMap.add(objectMap, "value1");
        String s = objectMap.toString();
        assertThat(s).contains("this map");
    }

    @Test
    void selfReferenceValue() {
        objectMap.add("key1", objectMap);
        String s = objectMap.toString();
        assertThat(s).contains("this map");
    }

    @Test
    void doNotPrintPassword() {
        map.add("password", "password-value");
        String s = map.toString();
        assertThat(s).contains("password")
                .doesNotContain("password-value")
                .contains("PROTECTED");
    }

    @Test
    void doNotPrintPasswordWhenArrayConstructorIsUsed() {
        for (LinkedMaskingMultiValueMap<String, Object> map :
                Arrays.asList(
                        new LinkedMaskingMultiValueMap<>("password", "code"),
                        new LinkedMaskingMultiValueMap<>(new String[]{"password", "code"}))) {
            map.add("password", "password-value");
            map.add("code", "code-value");
            String s = map.toString();
            assertThat(s).contains("password")
                    .doesNotContain("password-value")
                    .contains("code")
                    .doesNotContain("code-value")
                    .contains("PROTECTED");
        }
    }

    @Test
    void hash() {
        map.add("key1", "value1");
        map.add("key1", "value2");
        objectMap.add("key1", "value1");
        objectMap.add("key1", "value2");
        int hash1 = map.hashCode();
        int hash2 = objectMap.hashCode();
        assertThat(hash2).isEqualTo(hash1);
    }

    @Test
    void cyclicKeyHash() {
        objectMap.add(objectMap, "value1");
        objectMap.add(objectMap, "value2");
        LinkedMaskingMultiValueMap<Object, Object> objectMap2 = new LinkedMaskingMultiValueMap<>(
                "password");
        objectMap2.add(objectMap2, "value1");
        objectMap2.add(objectMap2, "value2");
        int hash1 = objectMap.hashCode();
        int hash2 = objectMap2.hashCode();
        assertThat(hash2).isEqualTo(hash1);
    }

    @Test
    void cyclicValueHash() {
        objectMap.add("key1", "value1");
        objectMap.add("key1", objectMap);

        LinkedMaskingMultiValueMap<Object, Object> objectMap2 = new LinkedMaskingMultiValueMap<>(
                "password");
        objectMap2.add("key1", "value1");
        objectMap2.add("key1", objectMap2);

        int hash1 = objectMap.hashCode();
        int hash2 = objectMap2.hashCode();
        assertThat(hash2).isEqualTo(hash1);
    }
}
