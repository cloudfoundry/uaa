package org.cloudfoundry.identity.uaa.provider.saml;

import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;

import javax.servlet.http.HttpServletRequest;

import static org.springframework.security.saml2.core.Saml2ParameterNames.RELAY_STATE;

public class RelayStateRelyingPartyRegistrationResolver implements RelyingPartyRegistrationResolver {

    private final RelyingPartyRegistrationResolver internalResolver;

    public RelayStateRelyingPartyRegistrationResolver(RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) {
        this.internalResolver = new DefaultRelyingPartyRegistrationResolver(relyingPartyRegistrationRepository);
    }

    @Override
    public RelyingPartyRegistration resolve(HttpServletRequest request, String relyingPartyRegistrationId) {
        if (relyingPartyRegistrationId == null) {
            String[] relayStates = request.getParameterValues(RELAY_STATE);
            if (relayStates != null && relayStates.length > 0) {
                relyingPartyRegistrationId = relayStates[0];
            }
        }

        return internalResolver.resolve(request, relyingPartyRegistrationId);
    }
}
