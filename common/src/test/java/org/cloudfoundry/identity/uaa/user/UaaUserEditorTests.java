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
