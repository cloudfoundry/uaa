package org.cloudfoundry.identity.uaa.zone;

import java.util.List;

import javax.validation.Valid;

import org.codehaus.jackson.map.annotate.JsonDeserialize;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

@JsonDeserialize
public class IdentityZoneCreationRequest {
	
	@Valid
	private IdentityZone identityZone;
	private List<BaseClientDetails> clientDetails;
	
	public IdentityZone getIdentityZone() {
		return identityZone;
	}
	public void setIdentityZone(IdentityZone identityZone) {
		this.identityZone = identityZone;
	}
	public List<BaseClientDetails> getClientDetails() {
		return clientDetails;
	}
	public void setClientDetails(List<BaseClientDetails> clientDetails) {
		this.clientDetails = clientDetails;
	}

}
