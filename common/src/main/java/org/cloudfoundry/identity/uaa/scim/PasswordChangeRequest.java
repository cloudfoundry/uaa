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
package org.cloudfoundry.identity.uaa.scim;

import java.util.Arrays;

import org.codehaus.jackson.map.annotate.JsonSerialize;
import org.springframework.util.Assert;

/**
 * @author Dave Syer
 * @author Luke Taylor
 */
@JsonSerialize (include = JsonSerialize.Inclusion.NON_NULL)
public class PasswordChangeRequest {

	private String oldPassword;
	private String password;

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getOldPassword() {
		return oldPassword;
	}

	public void setOldPassword(String oldPassword) {
		this.oldPassword = oldPassword;
	}

	public void setSchemas(String[] schemas) {
		Assert.isTrue(Arrays.equals(ScimUser.SCHEMAS, schemas), "Only schema '" + ScimUser.SCHEMAS[0] + "' is currently supported");
	}

	public String[] getSchemas() {
		return ScimUser.SCHEMAS;
	}

}
