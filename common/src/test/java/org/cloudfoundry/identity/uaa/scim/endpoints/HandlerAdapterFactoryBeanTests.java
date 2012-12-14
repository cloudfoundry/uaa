/**
 * Cloud Foundry 2012.02.03 Beta Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 * 
 * This product is licensed to you under the Apache License, Version 2.0 (the "License"). You may not use this product
 * except in compliance with the License.
 * 
 * This product includes a number of subcomponents with separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the subcomponent's license, as noted in the LICENSE file.
 */

package org.cloudfoundry.identity.uaa.scim.endpoints;

import static org.junit.Assert.assertNotNull;

import org.cloudfoundry.identity.uaa.scim.endpoints.HandlerAdapterFactoryBean;
import org.junit.Test;
import org.springframework.context.support.GenericApplicationContext;

/**
 * @author Dave Syer
 * 
 */
public class HandlerAdapterFactoryBeanTests {

	private HandlerAdapterFactoryBean factory = new HandlerAdapterFactoryBean();

	@Test
	public void testGetObject() throws Exception {
		factory.setApplicationContext(new GenericApplicationContext());
		assertNotNull(factory.getObject());
	}

}
