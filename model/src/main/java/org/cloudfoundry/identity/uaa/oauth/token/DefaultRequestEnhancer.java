package org.cloudfoundry.identity.uaa.oauth.token;

import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.util.MultiValueMap;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

public class DefaultRequestEnhancer implements RequestEnhancer {

	private Set<String> parameterIncludes = Collections.emptySet();
	
	public void setParameterIncludes(Collection<String> parameterIncludes) {
		this.parameterIncludes = new LinkedHashSet<String>(parameterIncludes);
	}

	@Override
	public void enhance(AccessTokenRequest request, OAuth2ProtectedResourceDetails resource, MultiValueMap<String, String> form, HttpHeaders headers) {
		for (String include : parameterIncludes) {
			if (request.containsKey(include)) {
				form.set(include, request.getFirst(include));
			}
		}
	}

}
