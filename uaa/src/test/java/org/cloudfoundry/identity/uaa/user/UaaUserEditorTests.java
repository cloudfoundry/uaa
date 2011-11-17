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
