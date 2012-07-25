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
		if (values.length < 5) {
			throw new IllegalArgumentException("Username, password, email, first and last names are required (use pipe separator '|')");
		}
		UaaUser user = new UaaUser(values[0], values[1], values[2], values[3], values[4]);
		if (values.length>5) {
			user = user.authorities(AuthorityUtils.commaSeparatedStringToAuthorityList(values[5]));
		}
		super.setValue(user);
	}

}
