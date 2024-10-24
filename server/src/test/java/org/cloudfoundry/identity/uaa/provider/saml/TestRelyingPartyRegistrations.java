/*
 * Copyright 2002-2023 the original author or authors.
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

import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2WebSsoAuthenticationFilter;

/**
 * This was copied from Spring Security Test Classes
 * Migrate to use the Spring Security class when it is made public
 * <p>
 * Modified to work with org.springframework.security.saml2.core.Saml2X509Credential
 * instead of now deprecated org.springframework.security.saml2.credentials.Saml2X509Credential;
 */
public final class TestRelyingPartyRegistrations {

    private TestRelyingPartyRegistrations() {
        throw new java.lang.UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    public static RelyingPartyRegistration.Builder relyingPartyRegistration() {
        String registrationId = "simplesamlphp";
        String rpEntityId = "{baseUrl}/saml2/service-provider-metadata/{registrationId}";
        Saml2X509Credential signingCredential = TestSaml2X509Credentials.relyingPartySigningCredential();
        String assertionConsumerServiceLocation = "{baseUrl}"
                + Saml2WebSsoAuthenticationFilter.DEFAULT_FILTER_PROCESSES_URI;
        String apEntityId = "https://simplesaml-for-spring-saml.apps.pcfone.io/saml2/idp/metadata.php";
        Saml2X509Credential verificationCertificate = TestSaml2X509Credentials.relyingPartyVerifyingCredential();
        String singleSignOnServiceLocation = "https://simplesaml-for-spring-saml.apps.pcfone.io/saml2/idp/SSOService.php";
        String singleLogoutServiceLocation = "{baseUrl}/logout/saml2/slo";
        return RelyingPartyRegistration.withRegistrationId(registrationId)
                .entityId(rpEntityId)
                .nameIdFormat("format")
                .assertionConsumerServiceLocation(assertionConsumerServiceLocation)
                .singleLogoutServiceLocation(singleLogoutServiceLocation)
                .assertingPartyDetails(c -> c.entityId(apEntityId).singleSignOnServiceLocation(singleSignOnServiceLocation))
                .signingX509Credentials(c -> c.add(signingCredential))
                .decryptionX509Credentials(c -> c.add(verificationCertificate));
    }

    public static RelyingPartyRegistration.Builder noCredentials() {
        return RelyingPartyRegistration.withRegistrationId("saml")//"registration-id")
                .entityId("rp-entity-id")
                .singleLogoutServiceLocation("https://rp.example.org/logout/saml2/request")
                .singleLogoutServiceResponseLocation("https://rp.example.org/logout/saml2/response")
                .assertionConsumerServiceLocation("https://rp.example.org/acs")
                .assertingPartyDetails(party -> party.entityId("ap-entity-id")
                        .singleSignOnServiceLocation("https://ap.example.org/sso")
                        .singleLogoutServiceLocation("https://ap.example.org/logout/saml2/request")
                        .singleLogoutServiceResponseLocation("https://ap.example.org/logout/saml2/response"));
    }

    public static RelyingPartyRegistration.Builder full() {
        return noCredentials()
                .signingX509Credentials(c -> c.add(TestSaml2X509Credentials.relyingPartySigningCredential()))
                .decryptionX509Credentials(c -> c.add(TestSaml2X509Credentials.relyingPartyDecryptingCredential()))
                .assertingPartyDetails(party -> party.verificationX509Credentials(
                        c -> c.add(TestSaml2X509Credentials.relyingPartyVerifyingCredential())));
    }
}
