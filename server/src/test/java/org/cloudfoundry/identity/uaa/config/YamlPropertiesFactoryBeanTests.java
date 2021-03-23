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

import static org.junit.Assert.assertEquals;

import java.util.Collections;
import java.util.Map;
import java.util.Properties;

import org.cloudfoundry.identity.uaa.impl.config.YamlProcessor.ResolutionMethod;
import org.cloudfoundry.identity.uaa.impl.config.YamlPropertiesFactoryBean;
import org.junit.Test;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.yaml.snakeyaml.Yaml;

/**
 * @author Dave Syer
 * 
 */
public class YamlPropertiesFactoryBeanTests {

    @Test
    public void testLoadResource() {
        YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
        factory.setResources(new Resource[] { new ByteArrayResource("foo: bar\nspam:\n  foo: baz".getBytes()) });
        Properties properties = factory.getObject();
        assertEquals("bar", properties.get("foo"));
        assertEquals("baz", properties.get("spam.foo"));
    }

    @Test
    public void testLoadResourcesWithOverride() {
        YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
        factory.setResources(new Resource[] { new ByteArrayResource("foo: bar\nspam:\n  foo: baz".getBytes()),
                        new ByteArrayResource("foo:\n  bar: spam".getBytes()) });
        Properties properties = factory.getObject();
        assertEquals("bar", properties.get("foo"));
        assertEquals("baz", properties.get("spam.foo"));
        assertEquals("spam", properties.get("foo.bar"));
    }

    @Test
    public void testLoadResourceWithMultipleDocuments() {
        YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
        factory.setResources(new Resource[] { new ByteArrayResource("foo: bar\nspam: baz\n---\nfoo: bag".getBytes()) });
        Properties properties = factory.getObject();
        assertEquals("bag", properties.get("foo"));
        assertEquals("baz", properties.get("spam"));
    }

    @Test
    public void testLoadResourceWithSelectedDocuments() {
        YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
        factory.setResources(new Resource[] { new ByteArrayResource("foo: bar\nspam: baz\n---\nfoo: bag\nspam: bad"
                        .getBytes()) });
        factory.setDocumentMatchers(Collections.singletonMap("foo", "bag"));
        Properties properties = factory.getObject();
        assertEquals("bag", properties.get("foo"));
        assertEquals("bad", properties.get("spam"));
    }

    @Test
    public void testLoadResourceWithDefaultMatch() {
        YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
        factory.setMatchDefault(true);
        factory.setResources(new Resource[] { new ByteArrayResource(
                        "one: two\n---\nfoo: bar\nspam: baz\n---\nfoo: bag\nspam: bad".getBytes()) });
        factory.setDocumentMatchers(Collections.singletonMap("foo", "bag"));
        Properties properties = factory.getObject();
        assertEquals("bag", properties.get("foo"));
        assertEquals("bad", properties.get("spam"));
        assertEquals("two", properties.get("one"));
    }

    @Test
    public void testLoadResourceWithDefaultMatchSkippingMissedMatch() {
        YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
        factory.setMatchDefault(true);
        factory.setResources(new Resource[] { new ByteArrayResource(
                        "one: two\n---\nfoo: bag\nspam: bad\n---\nfoo: bar\nspam: baz".getBytes()) });
        factory.setDocumentMatchers(Collections.singletonMap("foo", "bag"));
        Properties properties = factory.getObject();
        assertEquals("bag", properties.get("foo"));
        assertEquals("bad", properties.get("spam"));
        assertEquals("two", properties.get("one"));
    }

    @Test
    public void testLoadNonExistentResource() {
        YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
        factory.setResolutionMethod(ResolutionMethod.OVERRIDE_AND_IGNORE);
        factory.setResources(new Resource[] { new ClassPathResource("no-such-file.yml") });
        Properties properties = factory.getObject();
        assertEquals(0, properties.size());
    }

    @Test
    public void testLoadNull() {
        YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
        factory.setResources(new Resource[] { new ByteArrayResource("foo: bar\nspam:".getBytes()) });
        Properties properties = factory.getObject();
        assertEquals("bar", properties.get("foo"));
        assertEquals("", properties.get("spam"));
    }

    @Test
    public void testLoadArrayOfString() {
        YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
        factory.setResources(new Resource[] { new ByteArrayResource("foo:\n- bar\n- baz".getBytes()) });
        Properties properties = factory.getObject();
        assertEquals("bar", properties.get("foo[0]"));
        assertEquals("baz", properties.get("foo[1]"));
        assertEquals("bar,baz", properties.get("foo"));
    }

    @Test
    public void testLoadArrayOfObject() {
        YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
        factory.setResources(new Resource[] { new ByteArrayResource(
                        "foo:\n- bar:\n    spam: crap\n- baz\n- one: two\n  three: four".getBytes()) });
        Properties properties = factory.getObject();
        // System.err.println(properties);
        assertEquals("crap", properties.get("foo[0].bar.spam"));
        assertEquals("baz", properties.get("foo[1]"));
        assertEquals("two", properties.get("foo[2].one"));
        assertEquals("four", properties.get("foo[2].three"));
        assertEquals("{bar={spam=crap}},baz,{one=two, three=four}", properties.get("foo"));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testYaml() {
        Yaml yaml = new Yaml();
        Map<String, ?> map = yaml.loadAs("foo: bar\nspam:\n  foo: baz", Map.class);
        assertEquals("bar", map.get("foo"));
        assertEquals("baz", ((Map<String, Object>) map.get("spam")).get("foo"));
    }

}
