package org.cloudfoundry.identity.uaa.oauth.exceptions;

import org.cloudfoundry.identity.uaa.util.UaaOAuth2Utils;
import java.util.Set;

public class InvalidScopeException extends OAuth2Exception {

	public InvalidScopeException(String msg, Set<String> validScope) {
		this(msg);
		addAdditionalInformation("scope", UaaOAuth2Utils.formatParameterList(validScope));
	}

	public InvalidScopeException(String msg) {
		super(msg);
	}

	@Override
	public String getOAuth2ErrorCode() {
		return "invalid_scope";
	}

}