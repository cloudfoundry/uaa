/*******************************************************************************
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
package org.cloudfoundry.identity.uaa.config;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;

import org.cloudfoundry.identity.uaa.impl.config.NestedMapPropertySource;
import org.junit.Test;
import org.yaml.snakeyaml.Yaml;

import static org.junit.Assert.*;

/**
 * @author Dave Syer
 * 
 */
public class NestedMapPropertySourceTests {

    @Test
    public void testPropertyResource() {
        Yaml yaml = new Yaml();
        @SuppressWarnings("unchecked")
        Map<String, Object> map = yaml.loadAs("foo: bar\nspam:\n  foo: baz", Map.class);
        NestedMapPropertySource properties = new NestedMapPropertySource("map", map);
        assertEquals("bar", properties.getProperty("foo"));
        assertEquals("baz", properties.getProperty("spam.foo"));
    }

    @Test
    public void testPropertyMap() {
        Yaml yaml = new Yaml();
        @SuppressWarnings("unchecked")
        Map<String, Object> map = yaml.loadAs("foo: bar\nspam:\n  foo: baz", Map.class);
        NestedMapPropertySource properties = new NestedMapPropertySource("map", map);
        assertEquals("{foo=baz}", properties.getProperty("spam").toString());
        assertEquals("baz", properties.getProperty("spam.foo"));
    }

    @Test
    public void testPropertyNestedMap() {
        Yaml yaml = new Yaml();
        @SuppressWarnings("unchecked")
        Map<String, Object> map = yaml.loadAs("foo: bar\nspam:\n  foo:\n    baz: bucket",
                        Map.class);
        NestedMapPropertySource properties = new NestedMapPropertySource("map", map);
        assertEquals("{baz=bucket}", properties.getProperty("spam.foo").toString());
    }

    @Test
    public void testPropertyNull() {
        Yaml yaml = new Yaml();
        @SuppressWarnings("unchecked")
        Map<String, Object> map = yaml.loadAs("foo: bar\nspam:", Map.class);
        NestedMapPropertySource properties = new NestedMapPropertySource("map", map);
        assertEquals("bar", properties.getProperty("foo"));
        assertNull(properties.getProperty("spam"));
    }

    @Test
    public void testPropertyCycle() {
        Yaml yaml = new Yaml();
        @SuppressWarnings("unchecked")
        Map<String, Object> map = yaml.loadAs("foo: bar\nspam:", Map.class);
        map.put("self", map);
        NestedMapPropertySource properties = new NestedMapPropertySource("map", map);
        assertEquals(map, properties.getProperty("self"));
    }

    @Test
    public void testNestedPropertyCycle() {
        Yaml yaml = new Yaml();
        @SuppressWarnings("unchecked")
        Map<String, Object> map = yaml.loadAs("foo: bar\nspam:", Map.class);
        map.put("bang", Collections.singletonMap("self", map));
        NestedMapPropertySource properties = new NestedMapPropertySource("map", map);
        assertEquals(map, properties.getProperty("bang.self"));
    }

    @Test
    public void testNestedCollectionPropertyCycle() {
        Yaml yaml = new Yaml();
        @SuppressWarnings("unchecked")
        Map<String, Object> map = yaml.loadAs("foo: bar\nspam:", Map.class);
        map.put("bang", Collections.singleton(map));
        NestedMapPropertySource properties = new NestedMapPropertySource("map", map);
        assertEquals(map, properties.getProperty("bang[0]"));
    }

    @Test
    public void testPropertyArrayOfString() {
        Yaml yaml = new Yaml();
        @SuppressWarnings("unchecked")
        Map<String, Object> map = yaml.loadAs("foo:\n- bar\n- baz", Map.class);
        NestedMapPropertySource properties = new NestedMapPropertySource("map", map);
        assertEquals("bar", properties.getProperty("foo[0]"));
        assertEquals("baz", properties.getProperty("foo[1]"));
        assertEquals("[bar, baz]", properties.getProperty("foo").toString());
    }

    @Test
    public void testNestedPropertyArrayOfString() {
        Yaml yaml = new Yaml();
        @SuppressWarnings("unchecked")
        Map<String, Object> map = yaml.loadAs("foo:\n  baz:\n  - bar\n  - baz", Map.class);
        NestedMapPropertySource properties = new NestedMapPropertySource("map", map);
        assertEquals("bar", properties.getProperty("foo.baz[0]"));
        assertEquals("baz", properties.getProperty("foo.baz[1]"));
        assertTrue(properties.getProperty("foo.baz") instanceof Collection);
        assertEquals("[bar, baz]", properties.getProperty("foo.baz").toString());
    }

    @Test
    public void testPropertyArrayOfObject() {
        Yaml yaml = new Yaml();
        @SuppressWarnings("unchecked")
        Map<String, Object> map = yaml.loadAs(
                        "foo:\n- bar:\n    spam: crap\n- baz\n- one: two\n  three: four", Map.class);
        NestedMapPropertySource properties = new NestedMapPropertySource("map", map);
        // System.err.println(Map);
        assertEquals("crap", properties.getProperty("foo[0].bar.spam"));
        assertEquals("baz", properties.getProperty("foo[1]"));
        assertEquals("two", properties.getProperty("foo[2].one"));
        assertEquals("four", properties.getProperty("foo[2].three"));
        assertEquals("[{bar={spam=crap}}, baz, {one=two, three=four}]", properties.getProperty("foo").toString());
    }

}
