/*
 * Copyright 2002-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.cloudfoundry.identity.uaa.provider.saml;

import groovy.util.logging.Slf4j;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;
import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.NonNull;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ResponseValidatorResult;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Optional;

/**
 * Strategy for validating the SAML 2.0 Response used with
 * {@link org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider}
 * Handles the property `login.saml.disableInResponseToCheck` when set to true
 * we will ignore errors on the InResponseTo check of the SAML Response.
 * <p>
 * The InResponseTo attribute is optional, but if it is present, the default validator checks against the ID of the request.
 */
@Slf4j
public final class UaaInResponseToHandlingResponseValidator implements Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2ResponseValidatorResult> {

    private final boolean uaaWideDisableInResponseToCheck;
    private final Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2ResponseValidatorResult> delegate;

    public UaaInResponseToHandlingResponseValidator(Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2ResponseValidatorResult> delegate,
            boolean uaaWideDisableInResponseToCheck) {
        this.delegate = delegate;
        this.uaaWideDisableInResponseToCheck = uaaWideDisableInResponseToCheck;
    }

    @Override
    public Saml2ResponseValidatorResult convert(@NonNull OpenSaml4AuthenticationProvider.ResponseToken source) {
        Saml2ResponseValidatorResult result = delegate.convert(source);
        // if the result is successful, return it
        if (result == null || !result.hasErrors()) {
            return result;
        }

        // in case of error, check if we should ignore the InResponseTo check, and remove
        IdentityZone identityZone = IdentityZoneHolder.get();
        if (identityZone != null) {
            boolean removeInResponseToErrors = false;

            // samlConfig does not have correct values for UAA zone
            if (identityZone.isUaa() && uaaWideDisableInResponseToCheck) {
                removeInResponseToErrors = true;
            } else {
                removeInResponseToErrors = Optional.of(identityZone)
                        .map(IdentityZone::getConfig)
                        .map(IdentityZoneConfiguration::getSamlConfig)
                        .map(SamlConfig::isDisableInResponseToCheck)
                        .orElse(false);
            }

            if (removeInResponseToErrors) {
                result = removeInResponseToErrors(result);
            }
        }

        return result;
    }

    private Saml2ResponseValidatorResult removeInResponseToErrors(Saml2ResponseValidatorResult result) {

        Collection<Saml2Error> errors = new ArrayList<>(result.getErrors());
        errors.removeIf(error -> error.getErrorCode().contains("invalid_in_response_to"));

        if (errors.isEmpty()) {
            return Saml2ResponseValidatorResult.success();
        }
        return Saml2ResponseValidatorResult.failure(errors);
    }
}
