package org.cloudfoundry.identity.uaa.authentication;

import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.provider.service.authentication.logout.OpenSamlLogoutRequestValidator;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequestValidator;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequestValidatorParameters;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutValidatorResult;

import java.util.Collection;

/**
 * Delegates SAML logout request validation to {@link OpenSamlLogoutRequestValidator},
 * but ignores errors due to missing signatures.
 */
public class SamlLogoutRequestValidator implements Saml2LogoutRequestValidator {

    private final Saml2LogoutRequestValidator delegate;

    public SamlLogoutRequestValidator() {
        this.delegate = new OpenSamlLogoutRequestValidator();
    }

    public SamlLogoutRequestValidator(Saml2LogoutRequestValidator delegate) {
        this.delegate = delegate;
    }

    @Override
    public Saml2LogoutValidatorResult validate(Saml2LogoutRequestValidatorParameters parameters) {
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
