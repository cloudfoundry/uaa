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
package org.cloudfoundry.identity.uaa.authentication.login;

import static org.junit.Assert.assertEquals;

import org.cloudfoundry.identity.uaa.authentication.login.Prompt;
import org.junit.Test;

/**
 * @author Dave Syer
 *
 */
public class PromptEditorTests {
	
	private PromptEditor editor = new PromptEditor();

	@Test
	public void testDeserialization() throws Exception {
		editor.setAsText("username:[text,Username]");
		Prompt prompt = (Prompt) editor.getValue();
		String[] values = prompt.getDetails();
		assertEquals("text", values[0]);
		assertEquals("Username", values[1]);
	}

	@Test
	public void testSerialization() throws Exception {
		Prompt prompt = new Prompt("username", "text", "Username");
		editor.setValue(prompt);
		assertEquals("\"username\":[\"text\",\"Username\"]", editor.getAsText());
	}

}
