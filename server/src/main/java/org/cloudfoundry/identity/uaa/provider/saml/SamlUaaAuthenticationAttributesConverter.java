package org.cloudfoundry.identity.uaa.provider.saml;

import lombok.extern.slf4j.Slf4j;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.opensaml.core.xml.schema.XSURI;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.ObjectUtils;

import java.util.List;
import java.util.Map;
import java.util.Objects;

import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_ATTRIBUTE_PREFIX;
import static org.cloudfoundry.identity.uaa.provider.saml.SamlUaaAuthenticationUserManager.AUTHENTICATION_CONTEXT_CLASS_REFERENCE;

/**
 * Part of the AuthenticationConverter used during SAML login flow.
 * This handles the conversion of SAML Attributes to User Attributes
 */
@Slf4j
public class SamlUaaAuthenticationAttributesConverter {

    public MultiValueMap<String, String> retrieveUserAttributes(SamlIdentityProviderDefinition definition, List<Assertion> assertions) {
        log.debug("Retrieving SAML user attributes [zone:{}, origin:{}}]", definition.getZoneId(), definition.getIdpEntityAlias());
        MultiValueMap<String, String> userAttributes = new LinkedMultiValueMap<>();
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

        List<String> authnContextList = assertions.stream().flatMap(assertion -> assertion.getAuthnStatements().stream())
                .map(AuthnStatement::getAuthnContext).filter(Objects::nonNull)
                .map(AuthnContext::getAuthnContextClassRef).filter(Objects::nonNull)
                .map(XSURI::getURI).filter(Objects::nonNull).toList();
        if (!ObjectUtils.isEmpty(authnContextList)) {
            userAttributes.addAll(AUTHENTICATION_CONTEXT_CLASS_REFERENCE, authnContextList);
        }

        if (definition != null && definition.getAttributeMappings() != null) {
            definition.getAttributeMappings().forEach((key, attributeKey) -> {
                if (attributeKey instanceof String && userAttributes.get(attributeKey) != null) {
                    userAttributes.addAll(key, userAttributes.get(attributeKey));
                }
            });
        }

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
