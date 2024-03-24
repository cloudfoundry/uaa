package org.cloudfoundry.identity.uaa.oauth.exceptions;


import org.cloudfoundry.identity.uaa.util.UaaOAuth2Utils;

import java.util.Set;

public class InsufficientScopeException extends OAuth2Exception {

	public InsufficientScopeException(String msg, Set<String> validScope) {
		this(msg);
		addAdditionalInformation("scope", UaaOAuth2Utils.formatParameterList(validScope));
	}

	public InsufficientScopeException(String msg) {
		super(msg);
	}

	@Override
	public int getHttpErrorCode() {
		return 403;
	}

	@Override
	public String getOAuth2ErrorCode() {
		return "insufficient_scope";
	}

}