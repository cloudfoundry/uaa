package org.cloudfoundry.identity.uaa.oauth.client.state;

import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2ProtectedResourceDetails;

public interface StateKeyGenerator {

	/**
	 * Generate a key.
	 * 
	 * @param resource the resource to generate the key for
	 * @return a unique key for the state.  Never null.
	 */
	String generateKey(OAuth2ProtectedResourceDetails resource);

}
