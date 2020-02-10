/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.provider;

import org.cloudfoundry.identity.uaa.provider.ldap.LdapIdentityProviderConfigValidator;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthIdentityProviderConfigValidator;
import org.cloudfoundry.identity.uaa.provider.uaa.UaaIdentityProviderConfigValidator;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mockito;

import java.util.Arrays;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;

@SuppressWarnings("ALL")
public class IdentityProviderConfigValidationDelegatorTest {

    IdentityProviderConfigValidationDelegator validator;
    private UaaIdentityProviderConfigValidator uaaValidator;
    private LdapIdentityProviderConfigValidator ldapValidator;
    private IdentityProvider<AbstractIdentityProviderDefinition> provider;
    private ExternalOAuthIdentityProviderConfigValidator externalOAuthValidator;

    @Before
    public void setup() {
        uaaValidator = mock(UaaIdentityProviderConfigValidator.class);
        externalOAuthValidator = mock(ExternalOAuthIdentityProviderConfigValidator.class);
        ldapValidator = mock(LdapIdentityProviderConfigValidator.class);
        provider = new IdentityProvider<>();
        validator = new IdentityProviderConfigValidationDelegator(
                externalOAuthValidator,
                uaaValidator,
                ldapValidator
        );
    }

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void null_identity_provider() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Provider cannot be null");
        validator.validate(null);
    }

    @Test
    public void uaa_validator_with_nodefinition_is_invoked() {
        provider.setType(UAA);
        provider.setOriginKey(UAA);
        validator.validate(provider);
        verify(uaaValidator, times(1)).validate(same(provider));
        verifyZeroInteractions(externalOAuthValidator);
        verifyZeroInteractions(ldapValidator);
    }

    @Test
    public void ldap_validator_with_definition_is_invoked() {
        provider.setType(LDAP);
        provider.setOriginKey(LDAP);
        validator.validate(provider);
        verify(ldapValidator, times(1)).validate(same(provider));
        verifyZeroInteractions(uaaValidator);
        verifyZeroInteractions(externalOAuthValidator);
    }

    @Test
    public void externalOAuth_validator_with_definition_is_invoked() {
        for (String type : Arrays.asList(OAUTH20, OIDC10)) {
            provider.setType(type);
            provider.setOriginKey("any");
            validator.validate(provider);
            verify(externalOAuthValidator, times(1)).validate(same(provider));
            verifyZeroInteractions(uaaValidator);
            verifyZeroInteractions(ldapValidator);
            Mockito.reset(externalOAuthValidator);
        }
    }


}