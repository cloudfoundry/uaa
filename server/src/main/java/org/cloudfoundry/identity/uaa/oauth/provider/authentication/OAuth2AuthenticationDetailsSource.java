package org.cloudfoundry.identity.uaa.oauth.provider.authentication;


import org.springframework.security.authentication.AuthenticationDetailsSource;

import javax.servlet.http.HttpServletRequest;

public class OAuth2AuthenticationDetailsSource implements
		AuthenticationDetailsSource<HttpServletRequest, OAuth2AuthenticationDetails> {

	public OAuth2AuthenticationDetails buildDetails(HttpServletRequest context) {
		return new OAuth2AuthenticationDetails(context);
	}

}
