package org.cloudfoundry.identity.uaa.authorization;

import java.util.Set;

public interface ExternalGroupMappingAuthorizationManager {

	public Set<String> findScopesFromAuthorities(String authorities);

}
