package org.cloudfoundry.identity.uaa.oauth.common;

public enum AuthenticationScheme {

	/**
	 * Send an Authorization header.
	 */
	header,

	/**
	 * Send a query parameter in the URI.
	 */
	query,

	/**
	 * Send in the form body.
	 */
	form,

	/**
	 * Do not send at all.
	 */
	none
}