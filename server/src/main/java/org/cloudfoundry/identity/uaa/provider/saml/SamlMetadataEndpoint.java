package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.ZoneAware;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.metadata.Saml2MetadataResolver;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

@RestController
public class SamlMetadataEndpoint implements ZoneAware {
    protected static final String DEFAULT_REGISTRATION_ID = UUID.randomUUID().toString();
    private static final String APPLICATION_XML_CHARSET_UTF_8 = "application/xml; charset=UTF-8";

    private final Saml2MetadataResolver saml2MetadataResolver;

    private final RelyingPartyRegistrationResolver relyingPartyRegistrationResolver;

    public SamlMetadataEndpoint(RelyingPartyRegistrationResolver registrationResolver,
            IdentityZoneManager identityZoneManager, SignatureAlgorithm signatureAlgorithms,
            @Qualifier("signSamlMetaData") boolean signMetaData) {
        Assert.notNull(registrationResolver, "registrationResolver cannot be null");
        relyingPartyRegistrationResolver = registrationResolver;
        OpenSamlMetadataResolver metadataResolver = new OpenSamlMetadataResolver();
        saml2MetadataResolver = metadataResolver;
        metadataResolver.setEntityDescriptorCustomizer(
                new SamlMetadataEntityDescriptorCustomizer(identityZoneManager, signatureAlgorithms, signMetaData));
    }

    //Used in order to actually map 401 errors to invalid requests
    @GetMapping(value = "/saml/metadata/**", produces = APPLICATION_XML_CHARSET_UTF_8)
    public ResponseEntity<String> metadata401Error(HttpServletRequest request) {
        return ResponseEntity.status(HttpServletResponse.SC_UNAUTHORIZED).build();
    }

    @GetMapping(value = {"/saml/metadata", "/saml/metadata/"}, produces = APPLICATION_XML_CHARSET_UTF_8)
    public ResponseEntity<String> metadataEndpoint(HttpServletRequest request) {
        RelyingPartyRegistration relyingPartyRegistration = relyingPartyRegistrationResolver.resolve(request, DEFAULT_REGISTRATION_ID);
        if (relyingPartyRegistration == null) {
            return ResponseEntity.status(HttpServletResponse.SC_UNAUTHORIZED).build();
        }
        String metadata = saml2MetadataResolver.resolve(relyingPartyRegistration);

        String contentDisposition = ContentDispositionFilename.getContentDisposition(retrieveZone());
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, contentDisposition)
                .body(metadata);
    }
}

record ContentDispositionFilename(String fileName) {
    private static final String CONTENT_DISPOSITION_FORMAT = "attachment; filename=\"%s\"; filename*=UTF-8''%s";
    private static final String DEFAULT_FILE_NAME = "saml-sp.xml";

    static ContentDispositionFilename retrieveZoneAwareContentDispositionFilename(IdentityZone zone) {
        if (zone.isUaa()) {
            return new ContentDispositionFilename(DEFAULT_FILE_NAME);
        }
        String filename = "saml-%s-sp.xml".formatted(zone.getSubdomain());
        return new ContentDispositionFilename(filename);
    }

    static String getContentDisposition(IdentityZone zone) {
        return retrieveZoneAwareContentDispositionFilename(zone).getContentDisposition();
    }

    String getContentDisposition() {
        String encodedFileName = URLEncoder.encode(fileName, StandardCharsets.UTF_8);
        return CONTENT_DISPOSITION_FORMAT.formatted(fileName, encodedFileName);
    }
}
