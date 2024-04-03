package org.cloudfoundry.identity.uaa.oauth.provider.token;

public interface ConsumerTokenServices {
	
	boolean revokeToken(String tokenValue);

}
