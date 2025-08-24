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
package org.cloudfoundry.identity.uaa.config;

import org.cloudfoundry.identity.uaa.impl.config.NestedMapPropertySource;
import org.junit.jupiter.api.Test;
import org.yaml.snakeyaml.Yaml;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Dave Syer
 */
class NestedMapPropertySourceTests {

    @Test
    void propertyResource() {
        Yaml yaml = new Yaml();
        @SuppressWarnings("unchecked")
        Map<String, Object> map = yaml.loadAs("foo: bar\nspam:\n  foo: baz", Map.class);
        NestedMapPropertySource properties = new NestedMapPropertySource("map", map);
        assertThat(properties.getProperty("foo")).isEqualTo("bar");
        assertThat(properties.getProperty("spam.foo")).isEqualTo("baz");
    }

    @Test
    void propertyMap() {
        Yaml yaml = new Yaml();
        @SuppressWarnings("unchecked")
        Map<String, Object> map = yaml.loadAs("foo: bar\nspam:\n  foo: baz", Map.class);
        NestedMapPropertySource properties = new NestedMapPropertySource("map", map);
        assertThat(properties.getProperty("spam")).hasToString("{foo=baz}");
        assertThat(properties.getProperty("spam.foo")).isEqualTo("baz");
    }

    @Test
    void propertyNestedMap() {
        Yaml yaml = new Yaml();
        @SuppressWarnings("unchecked")
        Map<String, Object> map = yaml.loadAs("foo: bar\nspam:\n  foo:\n    baz: bucket",
                Map.class);
        NestedMapPropertySource properties = new NestedMapPropertySource("map", map);
        assertThat(properties.getProperty("spam.foo")).hasToString("{baz=bucket}");
    }

    @Test
    void propertyNull() {
        Yaml yaml = new Yaml();
        @SuppressWarnings("unchecked")
        Map<String, Object> map = yaml.loadAs("foo: bar\nspam:", Map.class);
        NestedMapPropertySource properties = new NestedMapPropertySource("map", map);
        assertThat(properties.getProperty("foo")).isEqualTo("bar");
        assertThat(properties.getProperty("spam")).isNull();
    }

    @Test
    void propertyCycle() {
        Yaml yaml = new Yaml();
        @SuppressWarnings("unchecked")
        Map<String, Object> map = yaml.loadAs("foo: bar\nspam:", Map.class);
        map.put("self", map);
        NestedMapPropertySource properties = new NestedMapPropertySource("map", map);
        assertThat(properties.getProperty("self")).isEqualTo(map);
    }

    @Test
    void nestedPropertyCycle() {
        Yaml yaml = new Yaml();
        @SuppressWarnings("unchecked")
        Map<String, Object> map = yaml.loadAs("foo: bar\nspam:", Map.class);
        map.put("bang", Collections.singletonMap("self", map));
        NestedMapPropertySource properties = new NestedMapPropertySource("map", map);
        assertThat(properties.getProperty("bang.self")).isEqualTo(map);
    }

    @Test
    void nestedCollectionPropertyCycle() {
        Yaml yaml = new Yaml();
        @SuppressWarnings("unchecked")
        Map<String, Object> map = yaml.loadAs("foo: bar\nspam:", Map.class);
        map.put("bang", Collections.singleton(map));
        NestedMapPropertySource properties = new NestedMapPropertySource("map", map);
        assertThat(properties.getProperty("bang[0]")).isEqualTo(map);
    }

    @Test
    void propertyArrayOfString() {
        Yaml yaml = new Yaml();
        @SuppressWarnings("unchecked")
        Map<String, Object> map = yaml.loadAs("foo:\n- bar\n- baz", Map.class);
        NestedMapPropertySource properties = new NestedMapPropertySource("map", map);
        assertThat(properties.getProperty("foo[0]")).isEqualTo("bar");
        assertThat(properties.getProperty("foo[1]")).isEqualTo("baz");
        assertThat(properties.getProperty("foo")).hasToString("[bar, baz]");
    }

    @Test
    void nestedPropertyArrayOfString() {
        Yaml yaml = new Yaml();
        @SuppressWarnings("unchecked")
        Map<String, Object> map = yaml.loadAs("foo:\n  baz:\n  - bar\n  - baz", Map.class);
        NestedMapPropertySource properties = new NestedMapPropertySource("map", map);
        assertThat(properties.getProperty("foo.baz[0]")).isEqualTo("bar");
        assertThat(properties.getProperty("foo.baz[1]")).isEqualTo("baz");
        assertThat(properties.getProperty("foo.baz")).isInstanceOf(Collection.class)
                .hasToString("[bar, baz]");
    }

    @Test
    void propertyArrayOfObject() {
        Yaml yaml = new Yaml();
        @SuppressWarnings("unchecked")
        Map<String, Object> map = yaml.loadAs(
                "foo:\n- bar:\n    spam: crap\n- baz\n- one: two\n  three: four", Map.class);
        NestedMapPropertySource properties = new NestedMapPropertySource("map", map);
        // System.err.println(Map);
        assertThat(properties.getProperty("foo[0].bar.spam")).isEqualTo("crap");
        assertThat(properties.getProperty("foo[1]")).isEqualTo("baz");
        assertThat(properties.getProperty("foo[2].one")).isEqualTo("two");
        assertThat(properties.getProperty("foo[2].three")).isEqualTo("four");
        assertThat(properties.getProperty("foo")).hasToString("[{bar={spam=crap}}, baz, {one=two, three=four}]");
    }
}
