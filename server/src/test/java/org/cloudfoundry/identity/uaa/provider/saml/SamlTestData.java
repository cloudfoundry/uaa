/*
 *  ****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2018] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 *  ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.provider.saml;

import java.time.Clock;

import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.spi.SpringSecuritySaml;
import org.springframework.security.saml.spi.opensaml.OpenSamlImplementation;

import static java.util.Arrays.asList;
import static org.cloudfoundry.identity.uaa.provider.saml.SamlTestKey.IDP_RSA_KEY;
import static org.cloudfoundry.identity.uaa.provider.saml.SamlTestKey.SP_RSA_KEY;

public class SamlTestData {

    private final String idpBaseUrl;
    private final String spBaseUrl;
    private Clock time = Clock.systemUTC();
    private SpringSecuritySaml implementation = new OpenSamlImplementation(time).init();
    private SamlTestObjectHelper helper;

    public SamlTestData(String idpBaseUrl, String spBaseUrl) {
        this.idpBaseUrl = idpBaseUrl;
        this.spBaseUrl = spBaseUrl;
        helper = new SamlTestObjectHelper(time);
    }

    public IdentityProviderMetadata getIdentityProvider() {
        SimpleKey idpKey = IDP_RSA_KEY.getSimpleKey("the-idp-key");
        return helper.identityProviderMetadata(idpBaseUrl,
                                               idpKey,
                                               asList(idpKey),
                                               "saml/idp",
                                               "the-idp",
                                               helper.DEFAULT_SIGN_ALGORITHM,
                                               helper.DEFAULT_SIGN_DIGEST);
    }


    public ServiceProviderMetadata getServiceProvider() {
        SimpleKey spKey = SP_RSA_KEY.getSimpleKey("the-sp-key");
        return helper.serviceProviderMetadata(spBaseUrl,
                                              spKey,
                                              asList(spKey),
                                              "saml",
                                              "the-sp",
                                              helper.DEFAULT_SIGN_ALGORITHM,
                                              helper.DEFAULT_SIGN_DIGEST);
    }

    public Assertion getAssertion(IdentityProviderMetadata idp, ServiceProviderMetadata sp) {
        return getAssertion(idp, sp, null);
    }

    public Assertion getAssertion(IdentityProviderMetadata idp,
            ServiceProviderMetadata sp,
            AuthenticationRequest request) {
        return helper.assertion(sp, idp, request, "testuser@test.org", NameId.EMAIL);
    }
}
