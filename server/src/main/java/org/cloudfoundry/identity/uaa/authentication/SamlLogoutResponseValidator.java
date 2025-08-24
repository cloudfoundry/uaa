package org.cloudfoundry.identity.uaa.authentication;

import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.provider.service.authentication.logout.OpenSamlLogoutResponseValidator;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponseValidator;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponseValidatorParameters;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutValidatorResult;

import java.util.Collection;

/**
 * Delegates SAML logout responses validation to {@link OpenSamlLogoutResponseValidator}
 * but ignores errors due to missing signatures.
 */

public class SamlLogoutResponseValidator implements Saml2LogoutResponseValidator {

    private final Saml2LogoutResponseValidator delegate;

    public SamlLogoutResponseValidator() {
        this.delegate = new OpenSamlLogoutResponseValidator();
    }

    public SamlLogoutResponseValidator(Saml2LogoutResponseValidator delegate) {
        this.delegate = delegate;
    }

    @Override
    public Saml2LogoutValidatorResult validate(Saml2LogoutResponseValidatorParameters parameters) {
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
