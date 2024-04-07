package org.cloudfoundry.identity.uaa.oauth.common;

import java.util.Date;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 client
 */
public class DefaultExpiringOAuth2RefreshToken extends DefaultOAuth2RefreshToken implements ExpiringOAuth2RefreshToken {

	private static final long serialVersionUID = 3449554332764129719L;

	private final Date expiration;

	/**
	 * @param value
	 */
	public DefaultExpiringOAuth2RefreshToken(String value, Date expiration) {
		super(value);
		this.expiration = expiration;
	}

	/**
	 * The instant the token expires.
	 * 
	 * @return The instant the token expires.
	 */
	public Date getExpiration() {
		return expiration;
	}

}
