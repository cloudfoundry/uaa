package org.cloudfoundry.identity.uaa.authorization;

import java.util.Set;

public class DoNothingExternalAuthorizationManager implements ExternalAuthorizationManager {

	@Override
	public Set<String> findScopesFromAuthorities(String authorities) {
		return null;
	}

}
