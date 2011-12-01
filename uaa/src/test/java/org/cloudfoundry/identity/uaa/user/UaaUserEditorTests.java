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
package org.cloudfoundry.identity.uaa.user;

import static org.junit.Assert.*;

import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserEditor;
import org.junit.Test;

public class UaaUserEditorTests {

	@Test
	public void testSetAsTextString() {
		UaaUserEditor editor = new UaaUserEditor();
		editor.setAsText("marissa|koala|marissa@test.org|Marissa|Bloggs");
		UaaUser user = (UaaUser) editor.getValue();
		assertEquals("marissa", user.getUsername());
		assertEquals("koala", user.getPassword());
		assertEquals("marissa@test.org", user.getEmail());
		assertEquals("Marissa", user.getGivenName());
		assertEquals("Bloggs", user.getFamilyName());
	}

}
