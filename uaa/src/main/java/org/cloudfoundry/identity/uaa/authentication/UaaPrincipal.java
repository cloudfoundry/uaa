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

	UaaPrincipal(UaaUser user) {
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
