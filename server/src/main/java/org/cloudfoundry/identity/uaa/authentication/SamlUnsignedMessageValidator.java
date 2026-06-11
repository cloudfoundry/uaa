package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.provider.saml.Saml2Utils;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutValidatorResult;
import org.springframework.security.saml2.provider.service.registration.AssertingPartyMetadata;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Non-signature validation for unsigned SAML logout messages.
 * <p>
 * Spring Security 7.1.0 throws NPE in {@code RedirectParameters} when {@code SigAlg}
 * is absent, so the standard validators cannot be called for unsigned messages.
 * This class replicates the issuer/destination/status checks that
 * {@code BaseOpenSamlLogoutResponseValidator.validateRequest()} would have run in 7.0.x.
 */
final class SamlUnsignedMessageValidator {

    private SamlUnsignedMessageValidator() {
    }

    /**
     * Validates a SAML LogoutResponse that arrived without a redirect-binding signature.
     * Checks issuer, destination, and status code.
     */
    static Saml2LogoutValidatorResult validateLogoutResponse(
            String encodedSaml, Saml2MessageBinding binding, RelyingPartyRegistration registration) {

        String xml = decodeSaml(encodedSaml, binding);
        if (xml == null) {
            return failure(Saml2ErrorCodes.MALFORMED_RESPONSE_DATA, "Failed to decode LogoutResponse");
        }

        Document doc = parseXml(xml);
        if (doc == null) {
            return failure(Saml2ErrorCodes.MALFORMED_RESPONSE_DATA, "Failed to parse LogoutResponse XML");
        }

        List<Saml2Error> errors = new ArrayList<>();
        AssertingPartyMetadata party = registration.getAssertingPartyMetadata();

        validateDestination(doc, registration.getSingleLogoutServiceResponseLocation(), errors);
        validateIssuer(doc, party.getEntityId(), "LogoutResponse", errors);

        NodeList statusCodes = doc.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:protocol", "StatusCode");
        if (statusCodes.getLength() > 0) {
            String statusValue = ((org.w3c.dom.Element) statusCodes.item(0)).getAttribute("Value");
            boolean ok = "urn:oasis:names:tc:SAML:2.0:status:Success".equals(statusValue)
                    || "urn:oasis:names:tc:SAML:2.0:status:PartialLogout".equals(statusValue);
            if (!ok) {
                errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_RESPONSE,
                        "Logout response status was not successful: " + statusValue));
            }
        }

        return toResult(errors);
    }

    /**
     * Validates a SAML LogoutRequest that arrived without a redirect-binding signature.
     * Checks issuer and destination.
     */
    static Saml2LogoutValidatorResult validateLogoutRequest(
            String encodedSaml, Saml2MessageBinding binding, RelyingPartyRegistration registration) {

        String xml = decodeSaml(encodedSaml, binding);
        if (xml == null) {
            return failure(Saml2ErrorCodes.MALFORMED_REQUEST_DATA, "Failed to decode LogoutRequest");
        }

        Document doc = parseXml(xml);
        if (doc == null) {
            return failure(Saml2ErrorCodes.MALFORMED_REQUEST_DATA, "Failed to parse LogoutRequest XML");
        }

        List<Saml2Error> errors = new ArrayList<>();
        AssertingPartyMetadata party = registration.getAssertingPartyMetadata();

        validateDestination(doc, registration.getSingleLogoutServiceLocation(), errors);
        validateIssuer(doc, party.getEntityId(), "LogoutRequest", errors);

        return toResult(errors);
    }

    private static String decodeSaml(String encoded, Saml2MessageBinding binding) {
        try {
            return (binding == Saml2MessageBinding.REDIRECT)
                    ? Saml2Utils.samlDecodeAndInflate(encoded)
                    : new String(Saml2Utils.samlDecode(encoded), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    private static Document parseXml(String xml) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            return factory.newDocumentBuilder().parse(new InputSource(new StringReader(xml)));
        } catch (Exception e) {
            return null;
        }
    }

    private static void validateDestination(Document doc, String expected, List<Saml2Error> errors) {
        if (expected == null) {
            return;
        }
        String destination = doc.getDocumentElement().getAttribute("Destination");
        if (!expected.equals(destination)) {
            errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_DESTINATION,
                    "Failed to match destination to configured destination"));
        }
    }

    private static void validateIssuer(Document doc, String expected, String messageType, List<Saml2Error> errors) {
        NodeList issuers = doc.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Issuer");
        if (issuers.getLength() == 0) {
            errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_ISSUER,
                    "Failed to find issuer in " + messageType));
            return;
        }
        String issuer = issuers.item(0).getTextContent();
        if (!expected.equals(issuer)) {
            errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_ISSUER,
                    "Failed to match issuer to configured issuer"));
        }
    }

    private static Saml2LogoutValidatorResult toResult(List<Saml2Error> errors) {
        return errors.isEmpty()
                ? Saml2LogoutValidatorResult.success()
                : Saml2LogoutValidatorResult.withErrors().errors(c -> c.addAll(errors)).build();
    }

    private static Saml2LogoutValidatorResult failure(String code, String description) {
        return Saml2LogoutValidatorResult.withErrors(new Saml2Error(code, description)).build();
    }
}
