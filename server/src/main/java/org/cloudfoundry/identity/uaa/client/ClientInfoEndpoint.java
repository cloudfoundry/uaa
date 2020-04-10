
package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.security.Principal;
import java.util.Collections;

/**
 * Controller which allows clients to inspect their own registration data.
 *
 * @author Dave Syer
 */
@Controller
public class ClientInfoEndpoint {

    private final MultitenantClientServices clientDetailsService;
    private final IdentityZoneManager identityZoneManager;

    public ClientInfoEndpoint(
            final @Qualifier("jdbcClientDetailsService") MultitenantClientServices clientDetailsService,
            final IdentityZoneManager identityZoneManager) {
        this.clientDetailsService = clientDetailsService;
        this.identityZoneManager = identityZoneManager;
    }

    @RequestMapping(value = "/clientinfo")
    @ResponseBody
    public ClientDetails clientinfo(Principal principal) {
        String clientId = principal.getName();
        BaseClientDetails client = new BaseClientDetails(clientDetailsService.loadClientByClientId(clientId, identityZoneManager.getCurrentIdentityZoneId()));
        client.setClientSecret(null);
        client.setAdditionalInformation(Collections.<String, Object> emptyMap());
        return client;
    }
}
