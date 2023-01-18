package org.cloudfoundry.identity.uaa.security.web;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.Collections;
import java.util.Set;

/**
 * By default, UAA only allows script-src 'self'. Custom script sources can be
 * configured here.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class ContentSecurityPolicyConfiguration {
	/*
	 * allowedScriptSrc corresponds to the `script-src` policy in a
	 * Content-Security-Policy header.
	 */
	private Set<String> allowedScriptSrc = Collections.singleton("'self'");

	public Set<String> getAllowedScriptSrc() {
		return allowedScriptSrc;
	}

	public void setAllowedScriptSrc(Set<String> allowedScriptSrc) {
		this.allowedScriptSrc = allowedScriptSrc;
	}
}
