/*
 * Copyright 2006-2011 the original author or authors.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.cloudfoundry.identity.uaa.authentication.login;

import static org.junit.Assert.assertEquals;

import org.cloudfoundry.identity.uaa.authentication.login.Prompt;
import org.junit.Test;

/**
 * @author Dave Syer
 *
 */
public class PromptTests {

	@Test
	public void testSerialization() throws Exception {
		Prompt prompt = new Prompt("username", "text", "Username");
		String[] values = prompt.getDetails();
		assertEquals("text", values[0]);
		assertEquals("Username", values[1]);
	}

	@Test
	public void testDeserialization() throws Exception {
		Prompt prompt = new Prompt("username", "text", "Username");
		Prompt value = Prompt.valueOf("username:[text,Username]");
		assertEquals(prompt, value);
	}

}
