package org.cloudfoundry.identity.uaa.authentication;

import static org.junit.Assert.*;

import org.junit.Test;

public class UaaUserEditorTests {

	@Test
	public void testSetAsTextString() {
		UaaUserEditor editor = new UaaUserEditor();
		editor.setAsText("marissa|koala|marissa@test.org");
		UaaUser user = (UaaUser) editor.getValue();
		assertEquals("marissa", user.getUsername());
		assertEquals("koala", user.getPassword());
		assertEquals("marissa@test.org", user.getEmail());
	}

}
