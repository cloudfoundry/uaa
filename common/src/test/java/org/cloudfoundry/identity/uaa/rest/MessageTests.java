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

package org.cloudfoundry.identity.uaa.rest;

import static org.junit.Assert.assertEquals;

import java.io.StringWriter;

import org.cloudfoundry.identity.uaa.message.SimpleMessage;
import org.codehaus.jackson.map.ObjectMapper;
import org.junit.Test;

/**
 * 
 * @author Dave Syer
 * 
 */
public class MessageTests {

	@Test
	public void testSerialize() throws Exception {
		StringWriter writer = new StringWriter();
		new ObjectMapper().writeValue(writer, new SimpleMessage("ok", "done"));
		assertEquals("{\"status\":\"ok\",\"message\":\"done\"}", writer.toString());
	}

	@Test
	public void testDeserialize() throws Exception {
		String value = "{\"status\":\"ok\",\"message\":\"done\"}";
		SimpleMessage message = new ObjectMapper().readValue(value, SimpleMessage.class);
		assertEquals(new SimpleMessage("ok", "done"), message);
	}

}
