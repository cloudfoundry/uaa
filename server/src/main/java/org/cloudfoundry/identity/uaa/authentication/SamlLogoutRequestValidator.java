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
        // redirect-binding logout request). Treat the absence of a signature as acceptable — consistent
        // with this validator's policy of not requiring signatures on logout messages.
        if (parameters != null && parameters.getLogoutRequest().getParameters().get(Saml2ParameterNames.SIG_ALG) == null) {
            return Saml2LogoutValidatorResult.success();
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
