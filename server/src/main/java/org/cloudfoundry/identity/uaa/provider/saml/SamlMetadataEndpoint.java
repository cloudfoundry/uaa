package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;
import org.cloudfoundry.identity.uaa.zone.ZoneAware;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.metadata.Saml2MetadataResolver;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletResponse;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.function.Consumer;

@RestController
public class SamlMetadataEndpoint implements ZoneAware {
    public static final String DEFAULT_REGISTRATION_ID = "example";
    private static final String APPLICATION_XML_CHARSET_UTF_8 = "application/xml; charset=UTF-8";

    private final Saml2MetadataResolver saml2MetadataResolver;
    private final IdentityZoneManager identityZoneManager;

    private final RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

    public SamlMetadataEndpoint(RelyingPartyRegistrationRepository relyingPartyRegistrationRepository,
                                IdentityZoneManager identityZoneManager) {
        Assert.notNull(relyingPartyRegistrationRepository, "relyingPartyRegistrationRepository cannot be null");
        this.relyingPartyRegistrationRepository = relyingPartyRegistrationRepository;
        this.identityZoneManager = identityZoneManager;
        OpenSamlMetadataResolver resolver = new OpenSamlMetadataResolver();
        this.saml2MetadataResolver = resolver;
        resolver.setEntityDescriptorCustomizer(new EntityDescriptorCustomizer());
    }

    private class EntityDescriptorCustomizer implements Consumer<OpenSamlMetadataResolver.EntityDescriptorParameters> {
        @Override
        public void accept(OpenSamlMetadataResolver.EntityDescriptorParameters entityDescriptorParameters) {
            SamlConfig samlConfig = identityZoneManager.getCurrentIdentityZone().getConfig().getSamlConfig();

            EntityDescriptor descriptor = entityDescriptorParameters.getEntityDescriptor();
            SPSSODescriptor spssodescriptor = descriptor.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
            spssodescriptor.setWantAssertionsSigned(samlConfig.isWantAssertionSigned());
            spssodescriptor.setAuthnRequestsSigned(samlConfig.isRequestSigned());
        }
    }

    @GetMapping(value = "/saml/metadata", produces = APPLICATION_XML_CHARSET_UTF_8)
    public ResponseEntity<String> legacyMetadataEndpoint() {
        return metadataEndpoint(DEFAULT_REGISTRATION_ID);
    }

    @GetMapping(value = "/saml/metadata/{registrationId}", produces = APPLICATION_XML_CHARSET_UTF_8)
    public ResponseEntity<String> metadataEndpoint(@PathVariable String registrationId) {
        RelyingPartyRegistration relyingPartyRegistration = relyingPartyRegistrationRepository.findByRegistrationId(registrationId);
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
