package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.scim.Queryable;
import org.cloudfoundry.identity.uaa.scim.ResourceManager;
import org.springframework.security.oauth2.provider.ClientDetails;

public interface ScimClientDetailsService extends Queryable<ClientDetails>, ResourceManager<ClientDetails> {
}
