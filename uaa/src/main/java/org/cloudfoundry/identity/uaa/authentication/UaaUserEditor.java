package org.cloudfoundry.identity.uaa.authentication;

import java.beans.PropertyEditorSupport;

public class UaaUserEditor extends PropertyEditorSupport {

	@Override
	public void setAsText(String text) throws IllegalArgumentException {
		String[] values = text.split("\\|");
		if (values.length < 2) {
			throw new IllegalArgumentException("At least username and password is required (use pipe separator '|')");
		}
		String username = values[0];
		String password = values[1];
		if (values.length > 2) {
			super.setValue(new UaaUser(username, password, values[2]));
		}
		else {
			super.setValue(new UaaUser(username, password, username + "@test.org"));
		}
	}

}
