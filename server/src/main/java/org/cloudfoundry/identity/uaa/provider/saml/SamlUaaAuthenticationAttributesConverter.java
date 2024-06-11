package org.cloudfoundry.identity.uaa.provider.saml;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_ATTRIBUTE_PREFIX;

/**
 * Part of the AuthenticationConverter used during SAML login flow.
 * This handles the conversion of SAML Attributes to User Attributes
 */
@Slf4j
public class SamlUaaAuthenticationAttributesConverter {

    public MultiValueMap<String, String> retrieveUserAttributes(SamlIdentityProviderDefinition definition, Response response) {
        log.debug("Retrieving SAML user attributes [zone:{}, origin:{}}]", definition.getZoneId(), definition.getIdpEntityAlias());
        MultiValueMap<String, String> userAttributes = new LinkedMultiValueMap<>();
        List<Assertion> assertions = response.getAssertions();
        if (assertions.isEmpty()) {
            return userAttributes;
        }

        assertions.stream().flatMap(assertion -> assertion.getAttributeStatements().stream())
                .flatMap(statement -> statement.getAttributes().stream())
                .forEach(attribute -> {
                    String key = attribute.getName();
                    attribute.getAttributeValues().forEach(xmlObject -> {
                        String value = OpenSamlXmlUtils.getStringValue(key, definition, xmlObject);
                        if (value != null) {
                            userAttributes.add(key, value);
                        }
                    });
                });

        if (definition != null && definition.getAttributeMappings() != null) {
            definition.getAttributeMappings().forEach((key, attributeKey) -> {
                if (attributeKey instanceof String && userAttributes.get(attributeKey) != null) {
                    userAttributes.addAll(key, userAttributes.get(attributeKey));
                }
            });
        }

//        if (credential.getAuthenticationAssertion() != null && credential.getAuthenticationAssertion().getAuthnStatements() != null) {
//            for (AuthnStatement statement : credential.getAuthenticationAssertion().getAuthnStatements()) {
//                if (statement.getAuthnContext() != null && statement.getAuthnContext().getAuthnContextClassRef() != null) {
//                    userAttributes.add(AUTHENTICATION_CONTEXT_CLASS_REFERENCE, statement.getAuthnContext().getAuthnContextClassRef().getAuthnContextClassRef());
//                }
//            }
//        }
        return userAttributes;
    }

    public MultiValueMap<String, String> retrieveCustomUserAttributes(MultiValueMap<String, String> userAttributes) {
        MultiValueMap<String, String> customAttributes = new LinkedMultiValueMap<>();
        for (Map.Entry<String, List<String>> entry : userAttributes.entrySet()) {
            if (entry.getKey().startsWith(USER_ATTRIBUTE_PREFIX)) {
                customAttributes.put(entry.getKey().substring(USER_ATTRIBUTE_PREFIX.length()), entry.getValue());
            }
        }
        return customAttributes;
    }
}
