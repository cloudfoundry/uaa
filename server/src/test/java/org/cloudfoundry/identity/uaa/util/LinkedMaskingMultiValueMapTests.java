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

import org.junit.Before;
import org.junit.Test;
import org.springframework.util.MultiValueMap;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * @author Arjen Poutsma
 * @author fhanik
 */
public class LinkedMaskingMultiValueMapTests {

    private LinkedMaskingMultiValueMap<String, String> map;
    private LinkedMaskingMultiValueMap<Object, Object> objectMap;

    @Before
    public void setUp() {
        map = new LinkedMaskingMultiValueMap<>("password");
        objectMap = new LinkedMaskingMultiValueMap<>("password");
    }

    @Test
    public void add() {
        map.add("key", "value1");
        map.add("key", "value2");
        assertEquals(1, map.size());
        List<String> expected = new ArrayList<String>(2);
        expected.add("value1");
        expected.add("value2");
        assertEquals(expected, map.get("key"));
    }

    @Test
    public void addAll() {
        map.add("key", "value1");
        map.addAll("key", Arrays.asList("value2", "value3"));
        assertEquals(1, map.size());
        assertEquals(3, map.get("key").size());
        assertEquals(Arrays.asList("value1", "value2", "value3"), map.get("key"));
    }

    @Test
    public void addAllFromAnotherMultiValueMap() {
        LinkedMaskingMultiValueMap<String, String> toCopy = new LinkedMaskingMultiValueMap<>();
        toCopy.add("key1", "value1");
        toCopy.add("key2", "value2");
        map.add("key1", "existing value");
        map.addAll(toCopy);
        assertEquals(2, map.size());
        assertEquals(2, map.get("key1").size());
        assertEquals(Arrays.asList("existing value", "value1"), map.get("key1"));
        assertEquals(1, map.get("key2").size());
        assertEquals(Collections.singletonList("value2"), map.get("key2"));
    }

    @Test
    public void getFirst() {
        List<String> values = new ArrayList<String>(2);
        values.add("value1");
        values.add("value2");
        map.put("key", values);
        assertEquals("value1", map.getFirst("key"));
        assertNull(map.getFirst("other"));
    }

    @Test
    public void set() {
        map.set("key", "value1");
        map.set("key", "value2");
        assertEquals(1, map.size());
        assertEquals(Collections.singletonList("value2"), map.get("key"));
    }

    @Test
    public void equals() {
        map.set("key1", "value1");
        assertEquals(map, map);
        MultiValueMap<String, String> o1 = new LinkedMaskingMultiValueMap<String, String>();
        o1.set("key1", "value1");
        assertEquals(map, o1);
        assertEquals(o1, map);
        Map<String, List<String>> o2 = new HashMap<String, List<String>>();
        o2.put("key1", Collections.singletonList("value1"));
        assertEquals(map, o2);
        assertEquals(o2, map);
    }

    @Test
    public void testSelfReferenceKey() {
        objectMap.add(objectMap, "value1");
        String s = objectMap.toString();
        assertTrue(s.contains("this map"));
    }

    @Test
    public void testSelfReferenceValue() {
        objectMap.add("key1", objectMap);
        String s = objectMap.toString();
        assertTrue(s.contains("this map"));
    }

    @Test
    public void doNotPrintPassword() {
        map.add("password", "password-value");
        String s = map.toString();
        assertTrue(s.contains("password"));
        assertFalse(s.contains("password-value"));
        assertTrue(s.contains("PROTECTED"));
    }

    @Test
    public void doNotPrintPasswordWhenArrayConstructorIsUsed() {
        for (LinkedMaskingMultiValueMap<String,Object> map :
            Arrays.asList(
                new LinkedMaskingMultiValueMap<>("password", "code"),
                new LinkedMaskingMultiValueMap<>(new String[] {"password", "code"}))) {
            map.add("password", "password-value");
            map.add("code", "code-value");
            String s = map.toString();
            assertTrue(s.contains("password"));
            assertFalse(s.contains("password-value"));
            assertTrue(s.contains("code"));
            assertFalse(s.contains("code-value"));
            assertTrue(s.contains("PROTECTED"));
        }
    }

    @Test
    public void testHash() {
        map.add("key1", "value1");
        map.add("key1", "value2");
        objectMap.add("key1", "value1");
        objectMap.add("key1", "value2");
        int hash1 = map.hashCode();
        int hash2 = objectMap.hashCode();
        assertEquals(hash1, hash2);
    }

    @Test
    public void testCyclicKeyHash() {
        objectMap.add(objectMap, "value1");
        objectMap.add(objectMap, "value2");
        LinkedMaskingMultiValueMap<Object, Object> objectMap2 = new LinkedMaskingMultiValueMap<Object, Object>(
                        "password");
        objectMap2.add(objectMap2, "value1");
        objectMap2.add(objectMap2, "value2");
        int hash1 = objectMap.hashCode();
        int hash2 = objectMap2.hashCode();
        assertEquals(hash1, hash2);
    }

    @Test
    public void testCyclicValueHash() {
        objectMap.add("key1", "value1");
        objectMap.add("key1", objectMap);

        LinkedMaskingMultiValueMap<Object, Object> objectMap2 = new LinkedMaskingMultiValueMap<Object, Object>(
                        "password");
        objectMap2.add("key1", "value1");
        objectMap2.add("key1", objectMap2);

        int hash1 = objectMap.hashCode();
        int hash2 = objectMap2.hashCode();
        assertEquals(hash1, hash2);
    }

}