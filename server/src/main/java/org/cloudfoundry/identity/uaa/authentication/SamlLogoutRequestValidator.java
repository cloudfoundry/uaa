package org.cloudfoundry.identity.uaa.authentication;

import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.logout.OpenSaml5LogoutRequestValidator;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequestValidator;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequestValidatorParameters;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutValidatorResult;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;

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
        // redirect-binding logout request). Restrict bypass to REDIRECT binding only — POST binding
        // uses XML signatures (not HTTP params) and must go through the delegate unchanged.
        if (parameters != null
                && parameters.getLogoutRequest().getBinding() == Saml2MessageBinding.REDIRECT
                && parameters.getLogoutRequest().getParameters().get(Saml2ParameterNames.SIG_ALG) == null) {
            // Signature present without SigAlg is malformed — reject rather than bypass.
            if (parameters.getLogoutRequest().getParameters().get(Saml2ParameterNames.SIGNATURE) != null) {
                return Saml2LogoutValidatorResult.withErrors(new Saml2Error(
                        Saml2ErrorCodes.INVALID_SIGNATURE, "Signature present without SigAlg")).build();
            }
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
