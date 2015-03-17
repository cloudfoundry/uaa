package org.cloudfoundry.identity.uaa.oauth;

import java.util.Collections;

import org.apache.commons.lang.StringUtils;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.client.ClientConstants;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

public class ZoneEndpointsClientDetailsValidator implements ClientDetailsValidator {

    @Override
    public ClientDetails validate(ClientDetails clientDetails, boolean create) throws InvalidClientDetailsException {
        
        if (!Collections.singleton("authorization_code").equals(clientDetails.getAuthorizedGrantTypes())) {
            throw new InvalidClientDetailsException("only authorization_code grant type is allowed");
        }
        if (!Collections.singleton("openid").equals(clientDetails.getScope())) {
            throw new InvalidClientDetailsException("only openid scope is allowed");
        }
        if (!Collections.singleton("uaa.resource").equals(AuthorityUtils.authorityListToSet(clientDetails.getAuthorities()))) {
            throw new InvalidClientDetailsException("only uaa.resource authority is allowed");
        }
        if (StringUtils.isBlank(clientDetails.getClientId())) {
            throw new InvalidClientDetailsException("client_id cannot be blank");
        }
        if (StringUtils.isBlank(clientDetails.getClientSecret())) {
            throw new InvalidClientDetailsException("client_secret cannot be blank");
        }
        if (!Collections.singletonList(Origin.UAA).equals(clientDetails.getAdditionalInformation().get(ClientConstants.ALLOWED_PROVIDERS))) {
            throw new InvalidClientDetailsException("only the internal IdP ('uaa') is allowed");
        }
        
        BaseClientDetails validatedClientDetails = new BaseClientDetails(clientDetails);
        
        validatedClientDetails.setResourceIds(Collections.singleton("none"));
        
            
        return validatedClientDetails;
    }
}
