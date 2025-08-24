package org.cloudfoundry.identity.uaa.provider.saml;

import lombok.extern.slf4j.Slf4j;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.core.xml.schema.XSBase64Binary;
import org.opensaml.core.xml.schema.XSBoolean;
import org.opensaml.core.xml.schema.XSBooleanValue;
import org.opensaml.core.xml.schema.XSDateTime;
import org.opensaml.core.xml.schema.XSInteger;
import org.opensaml.core.xml.schema.XSQName;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.XSURI;

import javax.xml.namespace.QName;
import java.time.Instant;

@Slf4j
public final class OpenSamlXmlUtils {

    private OpenSamlXmlUtils() {
        throw new java.lang.UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    public static String getStringValue(String key, SamlIdentityProviderDefinition definition, XMLObject xmlObject) {
        String value = null;
        if (xmlObject instanceof XSString xsString) {
            value = xsString.getValue();
        } else if (xmlObject instanceof XSAny xsAny) {
            value = xsAny.getTextContent();
        } else if (xmlObject instanceof XSInteger xsInteger) {
            Integer i = xsInteger.getValue();
            value = i != null ? i.toString() : null;
        } else if (xmlObject instanceof XSBoolean xsBoolean) {
            XSBooleanValue b = xsBoolean.getValue();
            value = b != null && b.getValue() != null ? b.getValue().toString() : null;
        } else if (xmlObject instanceof XSDateTime xsDateTime) {
            Instant d = xsDateTime.getValue();
            value = d != null ? d.toString() : null;
        } else if (xmlObject instanceof XSQName xsQName) {
            QName name = xsQName.getValue();
            value = name != null ? name.toString() : null;
        } else if (xmlObject instanceof XSURI xsUri) {
            value = xsUri.getURI();
        } else if (xmlObject instanceof XSBase64Binary xsBase64Binary) {
            value = xsBase64Binary.getValue();
        }

        if (value != null) {
            log.debug("Found SAML user attribute {} of value {} [zone:{}, origin:{}]", key, value, definition.getZoneId(), definition.getIdpEntityAlias());
            return value;
        } else if (xmlObject != null) {
            log.debug("SAML user attribute {} at is not of type XSString or other recognizable type, {} [zone:{}, origin:{}]", key, xmlObject.getClass().getName(), definition.getZoneId(), definition.getIdpEntityAlias());
        }
        return null;
    }
}
