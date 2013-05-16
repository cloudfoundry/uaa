package org.cloudfoundry.identity.uaa.authorization;

import java.util.Set;

public interface ExternalAuthorizationManager {

	public Set<String> findScopesFromAuthorities(String authorities);

}
