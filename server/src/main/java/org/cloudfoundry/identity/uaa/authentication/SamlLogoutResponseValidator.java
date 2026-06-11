package org.cloudfoundry.identity.uaa.authentication;

import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.logout.OpenSaml5LogoutResponseValidator;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponseValidator;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponseValidatorParameters;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutValidatorResult;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;

import java.util.Collection;

/**
 * Delegates SAML logout responses validation to {@link OpenSaml5LogoutResponseValidator}
 * but ignores errors due to missing signatures.
 */
public class SamlLogoutResponseValidator implements Saml2LogoutResponseValidator {

    private final Saml2LogoutResponseValidator delegate;

    public SamlLogoutResponseValidator() {
        this.delegate = new OpenSaml5LogoutResponseValidator();
    }

    public SamlLogoutResponseValidator(Saml2LogoutResponseValidator delegate) {
        this.delegate = delegate;
    }

    @Override
    public Saml2LogoutValidatorResult validate(Saml2LogoutResponseValidatorParameters parameters) {
        // Spring Security 7.1.0 throws NPE in RedirectParameters when SigAlg is absent (unsigned
        // redirect-binding logout response). Restrict bypass to REDIRECT binding only — POST binding
        // uses XML signatures (not HTTP params) and must go through the delegate unchanged.
        if (parameters != null
                && parameters.getLogoutResponse().getBinding() == Saml2MessageBinding.REDIRECT
                && parameters.getLogoutResponse().getParameters().get(Saml2ParameterNames.SIG_ALG) == null) {
            // Signature present without SigAlg is malformed — reject rather than bypass.
            if (parameters.getLogoutResponse().getParameters().get(Saml2ParameterNames.SIGNATURE) != null) {
                return Saml2LogoutValidatorResult.withErrors(new Saml2Error(
                        Saml2ErrorCodes.INVALID_SIGNATURE, "Signature present without SigAlg")).build();
            }
            return SamlUnsignedMessageValidator.validateLogoutResponse(
                    parameters.getLogoutResponse().getSamlResponse(),
                    parameters.getLogoutResponse().getBinding(),
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
