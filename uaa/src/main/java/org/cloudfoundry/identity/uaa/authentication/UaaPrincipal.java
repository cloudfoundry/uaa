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
package org.cloudfoundry.identity.uaa.authentication;

import java.io.Serializable;
import java.security.Principal;

import org.cloudfoundry.identity.uaa.user.UaaUser;

/**
 * The principal object which should end up as the representation of an authenticated user.
 * <p>
 * Contains the data required for an authenticated user within the UAA application itself.
 */
public class UaaPrincipal implements Principal, Serializable {
	private final String id;
	private final String name;
	private final String email;

	public UaaPrincipal(UaaUser user) {
		this.id = user.getId();
		this.name = user.getUsername();
		this.email = user.getEmail();
	}

	public String getId() {
		return id;
	}

	@Override
	public String getName() {
		return name;
	}

	public String getEmail() {
		return email;
	}

}
