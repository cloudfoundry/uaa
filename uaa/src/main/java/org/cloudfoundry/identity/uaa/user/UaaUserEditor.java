package org.cloudfoundry.identity.uaa.user;

import java.beans.PropertyEditorSupport;

public class UaaUserEditor extends PropertyEditorSupport {

	@Override
	public void setAsText(String text) throws IllegalArgumentException {
		String[] values = text.split("\\|");
		if (values.length < 4) {
			throw new IllegalArgumentException("Username, password, email, first and last names are required (use pipe separator '|')");
		}
		super.setValue(new UaaUser(values[0], values[1], values[2], values[3], values[4]));
	}

}
