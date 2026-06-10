package org.cloudfoundry.identity.uaa.authentication;

import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.logout.OpenSaml5LogoutRequestValidator;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequestValidator;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequestValidatorParameters;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutValidatorResult;

import java.util.Collection;

/**
 * Delegates SAML logout request validation to {@link OpenSaml5LogoutRequestValidator},
 * but ignores errors due to missing signatures.
 */
public class SamlLogoutRequestValidator implements Saml2LogoutRequestValidator {

    private final Saml2LogoutRequestValidator delegate;

    public SamlLogoutRequestValidator() {
        this.delegate = new OpenSaml5LogoutRequestValidator();
    }

    public SamlLogoutRequestValidator(Saml2LogoutRequestValidator delegate) {
        this.delegate = delegate;
    }

    @Override
    public Saml2LogoutValidatorResult validate(Saml2LogoutRequestValidatorParameters parameters) {
        // Spring Security 7.1.0 throws NPE in RedirectParameters when SigAlg is absent (unsigned
        // redirect-binding logout request). When no signature is present, we skip the delegate
        // (which would throw) and run only the non-signature checks directly, bypassing signature
        // verification but still ensuring issuer and destination are validated.
        if (parameters != null && parameters.getLogoutRequest().getParameters().get(Saml2ParameterNames.SIG_ALG) == null) {
            return SamlUnsignedMessageValidator.validateLogoutRequest(
                    parameters.getLogoutRequest().getSamlRequest(),
                    parameters.getLogoutRequest().getBinding(),
                    parameters.getRelyingPartyRegistration());
        }

        Saml2LogoutValidatorResult result = delegate.validate(parameters);
        if (!result.hasErrors()) {
            return result;
        }

        Collection<Saml2Error> errors = result.getErrors().stream()
                .filter(error -> !error.getDescription().contains("signature"))
                .toList();
        return Saml2LogoutValidatorResult.withErrors().errors(c -> c.addAll(errors)).build();
    }
}
