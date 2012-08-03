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

import java.beans.PropertyEditorSupport;

import org.springframework.security.core.authority.AuthorityUtils;

public class UaaUserEditor extends PropertyEditorSupport {

	@Override
	public void setAsText(String text) throws IllegalArgumentException {
		String[] values = text.split("\\|");
		if (values.length < 2) {
			throw new IllegalArgumentException("Specify at least a username and password. You may also optionally specify email, first name, last name and authorities (use pipe separator '|')");
		}

		String username = values[0], password = values[1];
		String email = username, firstName = username, lastName = username;
		String authorities = null;

		for (int i = 2; i < values.length; i++) {
			if (values[i].contains("@")) {
				email = values[i];
			} else if (values[i].contains(",") || values[i].contains(".")) {
				authorities = values[i];
			} else {
				if ((i+1) < values.length) {
					firstName = values[i];
					lastName = values[++i];
				} else {
					 authorities = values[i];
				}
			}
		}

		UaaUser user = new UaaUser(username, password, email, firstName, lastName);
		if (authorities != null) {
			user = user.authorities(AuthorityUtils.commaSeparatedStringToAuthorityList(authorities));
		}
		super.setValue(user);
	}

}
