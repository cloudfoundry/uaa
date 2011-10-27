package org.cloudfoundry.identity.uaa.authentication;

import java.io.Serializable;
import java.security.Principal;

/**
 * The principal object which should end up as the representation of an authenticated user.
 * <p>
 * Contains the full data for a system user (TODO: or will).
 */
public class UaaPrincipal implements Principal, Serializable {
	private final String id;
	private final String name;
	private final String email;

	UaaPrincipal(String id, String name, String email) {
		this.id = id;
		this.name = name;
		this.email = email;
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
