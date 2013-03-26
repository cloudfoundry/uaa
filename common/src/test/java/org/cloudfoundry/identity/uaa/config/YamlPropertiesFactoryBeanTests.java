/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */
package org.cloudfoundry.identity.uaa.config;

import static org.junit.Assert.assertEquals;

import java.util.Collections;
import java.util.Map;
import java.util.Properties;

import org.cloudfoundry.identity.uaa.config.YamlProcessor.ResolutionMethod;
import org.junit.Ignore;
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
	public void testLoadResource() throws Exception {
		YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
		factory.setResources(new Resource[] {new ByteArrayResource("foo: bar\nspam:\n  foo: baz".getBytes())});
		Properties properties = factory.getObject();
		assertEquals("bar", properties.get("foo"));
		assertEquals("baz", properties.get("spam.foo"));
	}

	@Test
	public void testLoadResourcesWithOverride() throws Exception {
		YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
		factory.setResources(new Resource[] {new ByteArrayResource("foo: bar\nspam:\n  foo: baz".getBytes()), new ByteArrayResource("foo:\n  bar: spam".getBytes())});
		Properties properties = factory.getObject();
		assertEquals("bar", properties.get("foo"));
		assertEquals("baz", properties.get("spam.foo"));
		assertEquals("spam", properties.get("foo.bar"));
	}

	@Test
	@Ignore // We can't fail on duplicate keys because the Map is created by the YAML library
	public void testLoadResourcesWithInternalOverride() throws Exception {
		YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
		factory.setResources(new Resource[] {new ByteArrayResource("foo: bar\nspam:\n  foo: baz\nfoo: bucket".getBytes())});
		Properties properties = factory.getObject();
		assertEquals("bar", properties.get("foo"));
	}

	@Test
	@Ignore // We can't fail on duplicate keys because the Map is created by the YAML library
	public void testLoadResourcesWithNestedInternalOverride() throws Exception {
		YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
		factory.setResources(new Resource[] {new ByteArrayResource("foo:\n  bar: spam\n  foo: baz\nbreak: it\nfoo: bucket".getBytes())});
		Properties properties = factory.getObject();
		assertEquals("spam", properties.get("foo.bar"));
	}

	@Test
	public void testLoadResourceWithMultipleDocuments() throws Exception {
		YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
		factory.setResources(new Resource[] {new ByteArrayResource("foo: bar\nspam: baz\n---\nfoo: bag".getBytes())});
		Properties properties = factory.getObject();
		assertEquals("bag", properties.get("foo"));
		assertEquals("baz", properties.get("spam"));
	}

	@Test
	public void testLoadResourceWithSelectedDocuments() throws Exception {
		YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
		factory.setResources(new Resource[] {new ByteArrayResource("foo: bar\nspam: baz\n---\nfoo: bag\nspam: bad".getBytes())});
		factory.setDocumentMatchers(Collections.singletonMap("foo", "bag"));
		Properties properties = factory.getObject();
		assertEquals("bag", properties.get("foo"));
		assertEquals("bad", properties.get("spam"));
	}

	@Test
	public void testLoadResourceWithDefaultMatch() throws Exception {
		YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
		factory.setMatchDefault(true);
		factory.setResources(new Resource[] {new ByteArrayResource("one: two\n---\nfoo: bar\nspam: baz\n---\nfoo: bag\nspam: bad".getBytes())});
		factory.setDocumentMatchers(Collections.singletonMap("foo", "bag"));
		Properties properties = factory.getObject();
		assertEquals("bag", properties.get("foo"));
		assertEquals("bad", properties.get("spam"));
		assertEquals("two", properties.get("one"));
	}

	@Test
	public void testLoadResourceWithDefaultMatchSkippingMissedMatch() throws Exception {
		YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
		factory.setMatchDefault(true);
		factory.setResources(new Resource[] {new ByteArrayResource("one: two\n---\nfoo: bag\nspam: bad\n---\nfoo: bar\nspam: baz".getBytes())});
		factory.setDocumentMatchers(Collections.singletonMap("foo", "bag"));
		Properties properties = factory.getObject();
		assertEquals("bag", properties.get("foo"));
		assertEquals("bad", properties.get("spam"));
		assertEquals("two", properties.get("one"));
	}

	@Test
	public void testLoadNonExistentResource() throws Exception {
		YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
		factory.setResolutionMethod(ResolutionMethod.OVERRIDE_AND_IGNORE);
		factory.setResources(new Resource[] {new ClassPathResource("no-such-file.yml")});
		Properties properties = factory.getObject();
		assertEquals(0, properties.size());
	}

	@Test
	public void testLoadNull() throws Exception {
		YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
		factory.setResources(new Resource[] {new ByteArrayResource("foo: bar\nspam:".getBytes())});
		Properties properties = factory.getObject();
		assertEquals("bar", properties.get("foo"));
		assertEquals("", properties.get("spam"));
	}

	@Test
	public void testLoadArrayOfString() throws Exception {
		YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
		factory.setResources(new Resource[] {new ByteArrayResource("foo:\n- bar\n- baz".getBytes())});
		Properties properties = factory.getObject();
		assertEquals("bar", properties.get("foo[0]"));
		assertEquals("baz", properties.get("foo[1]"));
		assertEquals("bar,baz", properties.get("foo"));
	}

	@Test
	public void testLoadArrayOfObject() throws Exception {
		YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
		factory.setResources(new Resource[] {new ByteArrayResource("foo:\n- bar:\n    spam: crap\n- baz\n- one: two\n  three: four".getBytes())});
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
		Map<String, ?> map = (Map<String, Object>) yaml.loadAs("foo: bar\nspam:\n  foo: baz", Map.class);
		assertEquals("bar", map.get("foo"));
		assertEquals("baz", ((Map<String,Object>)map.get("spam")).get("foo"));
	}

}
