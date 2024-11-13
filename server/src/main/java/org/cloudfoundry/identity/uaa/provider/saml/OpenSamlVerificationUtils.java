/*
 * Copyright 2002-2021 the original author or authors.
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

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.criterion.ProtocolCriterion;
import org.opensaml.saml.metadata.criteria.role.impl.EvaluableProtocolRoleDescriptorCriterion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.StatusResponseType;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialResolver;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.credential.criteria.impl.EvaluableEntityIDCredentialCriterion;
import org.opensaml.security.credential.criteria.impl.EvaluableUsageCredentialCriterion;
import org.opensaml.security.credential.impl.CollectionCredentialResolver;
import org.opensaml.security.criteria.UsageCriterion;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.core.Saml2ResponseValidatorResult;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * This class was copied from Spring Security 5.6.0 to get the OpenSaml4AuthenticationProvider to work.
 * It should be removed once we are able to more to the spring-security version of OpenSaml4AuthenticationProvider.
 * <p/>
 * Utility methods for verifying SAML component signatures with OpenSAML
 * <p>
 * For internal use only.
 *
 * @author Josh Cummings
 */
final class OpenSamlVerificationUtils {

    static VerifierPartial verifySignature(StatusResponseType object, RelyingPartyRegistration registration) {
        return new VerifierPartial(object, registration);
    }

    static SignatureTrustEngine trustEngine(RelyingPartyRegistration registration) {
        Set<Credential> credentials = new HashSet<>();
        Collection<Saml2X509Credential> keys = registration.getAssertingPartyDetails().getVerificationX509Credentials();
        for (Saml2X509Credential key : keys) {
            BasicX509Credential cred = new BasicX509Credential(key.getCertificate());
            cred.setUsageType(UsageType.SIGNING);
            cred.setEntityId(registration.getAssertingPartyDetails().getEntityId());
            credentials.add(cred);
        }
        CredentialResolver credentialsResolver = new CollectionCredentialResolver(credentials);
        return new ExplicitKeySignatureTrustEngine(credentialsResolver,
                DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver());
    }

    private OpenSamlVerificationUtils() {

    }

    static class VerifierPartial {

        private static final String INVALID_SIGNATURE_FOR_OBJECT = "Invalid signature for object [%s]";
        private static final String INVALID_SIGNATURE_FOR_OBJECT_COLON = "Invalid signature for object [%s]: ";

        private final String id;

        private final CriteriaSet criteria;

        private final SignatureTrustEngine trustEngine;

        VerifierPartial(StatusResponseType object, RelyingPartyRegistration registration) {
            this.id = object.getID();
            this.criteria = verificationCriteria(object.getIssuer());
            this.trustEngine = trustEngine(registration);
        }

        Saml2ResponseValidatorResult post(Signature signature) {
            Collection<Saml2Error> errors = new ArrayList<>();
            SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
            try {
                profileValidator.validate(signature);
            } catch (Exception ex) {
                errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE,
                        INVALID_SIGNATURE_FOR_OBJECT_COLON.formatted(this.id)));
            }

            try {
                if (!this.trustEngine.validate(signature, this.criteria)) {
                    errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE,
                            INVALID_SIGNATURE_FOR_OBJECT.formatted(this.id)));
                }
            } catch (Exception ex) {
                errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE,
                        INVALID_SIGNATURE_FOR_OBJECT_COLON.formatted(this.id)));
            }

            return Saml2ResponseValidatorResult.failure(errors);
        }

        private CriteriaSet verificationCriteria(Issuer issuer) {
            CriteriaSet criteriaSet = new CriteriaSet();
            criteriaSet.add(new EvaluableEntityIDCredentialCriterion(new EntityIdCriterion(issuer.getValue())));
            criteriaSet.add(new EvaluableProtocolRoleDescriptorCriterion(new ProtocolCriterion(SAMLConstants.SAML20P_NS)));
            criteriaSet.add(new EvaluableUsageCredentialCriterion(new UsageCriterion(UsageType.SIGNING)));
            return criteriaSet;
        }

    }
}
