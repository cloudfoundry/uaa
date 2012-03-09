/**
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

import java.io.FileNotFoundException;

import org.junit.Test;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.FileSystemResource;

/**
 * @author Dave Syer
 *
 */
public class YamlMapFactoryBeanTests {
	
	private YamlMapFactoryBean factory = new YamlMapFactoryBean();

	@Test
	public void testSetIgnoreResourceNotFound() throws Exception {
		factory.setIgnoreResourceNotFound(true);
		factory.setResources(new FileSystemResource[] {new FileSystemResource("non-exsitent-file.yml")});
		assertEquals(0, factory.getObject().size());
	}

	@Test(expected=FileNotFoundException.class)
	public void testSetBarfOnResourceNotFound() throws Exception {
		factory.setResources(new FileSystemResource[] {new FileSystemResource("non-exsitent-file.yml")});
		assertEquals(0, factory.getObject().size());
	}

	@Test
	public void testGetObject() throws Exception {
		factory.setResources(new ByteArrayResource[] {new ByteArrayResource("foo: bar".getBytes())});
		assertEquals(1, factory.getObject().size());
	}

}
