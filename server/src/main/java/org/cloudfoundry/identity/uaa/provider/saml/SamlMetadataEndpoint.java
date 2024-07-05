package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.ZoneAware;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.metadata.Saml2MetadataResolver;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.function.Consumer;

@RestController
public class SamlMetadataEndpoint implements ZoneAware {
    public static final String DEFAULT_REGISTRATION_ID = "example";
    private static final String DEFAULT_FILE_NAME = "saml-sp.xml";
    private static final String APPLICATION_XML_CHARSET_UTF_8 = "application/xml; charset=UTF-8";
    private static final String CONTENT_DISPOSITION_FORMAT = "attachment; filename=\"%s\"; filename*=UTF-8''%s";

    // @todo - this should be a Zone aware resolver
    private final RelyingPartyRegistrationResolver relyingPartyRegistrationResolver;
    private final Saml2MetadataResolver saml2MetadataResolver;

    private String fileName;
    private String encodedFileName;

    private final Boolean wantAssertionSigned;
    private final RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

    public SamlMetadataEndpoint(RelyingPartyRegistrationRepository relyingPartyRegistrationRepository,
                                SamlConfigProps samlConfigProps) {
        Assert.notNull(relyingPartyRegistrationRepository, "relyingPartyRegistrationRepository cannot be null");
        this.relyingPartyRegistrationRepository = relyingPartyRegistrationRepository;
        this.relyingPartyRegistrationResolver = new DefaultRelyingPartyRegistrationResolver(relyingPartyRegistrationRepository);
        OpenSamlMetadataResolver resolver = new OpenSamlMetadataResolver();
        this.saml2MetadataResolver = resolver;
        resolver.setEntityDescriptorCustomizer(new EntityDescriptorCustomizer());
        this.wantAssertionSigned = samlConfigProps.getWantAssertionSigned();
        setFileName(DEFAULT_FILE_NAME);
    }

    private class EntityDescriptorCustomizer implements Consumer<OpenSamlMetadataResolver.EntityDescriptorParameters> {
        @Override
        public void accept(OpenSamlMetadataResolver.EntityDescriptorParameters entityDescriptorParameters) {
            EntityDescriptor descriptor = entityDescriptorParameters.getEntityDescriptor();
            SPSSODescriptor spssodescriptor = descriptor.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
            spssodescriptor.setWantAssertionsSigned(wantAssertionSigned);
            spssodescriptor.setAuthnRequestsSigned(entityDescriptorParameters.getRelyingPartyRegistration().getAssertingPartyDetails().getWantAuthnRequestsSigned());
        }
    }

    @GetMapping(value = "/saml/metadata", produces = APPLICATION_XML_CHARSET_UTF_8)
    public ResponseEntity<String> legacyMetadataEndpoint(HttpServletRequest request) {
        return metadataEndpoint(DEFAULT_REGISTRATION_ID, request);
    }

    @GetMapping(value = "/saml/metadata/{registrationId}", produces = APPLICATION_XML_CHARSET_UTF_8)
    public ResponseEntity<String> metadataEndpoint(@PathVariable String registrationId, HttpServletRequest request) {
        RelyingPartyRegistration relyingPartyRegistration = relyingPartyRegistrationRepository.findByRegistrationId(registrationId);
        if (relyingPartyRegistration == null) {
            return ResponseEntity.status(HttpServletResponse.SC_UNAUTHORIZED).build();
        }
        String metadata = saml2MetadataResolver.resolve(relyingPartyRegistration);

        // @todo - fileName may need to be dynamic based on registrationID
        String[] fileNames = retrieveZoneAwareFileNames();
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, String.format(
                        CONTENT_DISPOSITION_FORMAT, fileNames[0], fileNames[1]))
                .body(metadata);
    }

    public void setFileName(String fileName) {
        encodedFileName = URLEncoder.encode(fileName, StandardCharsets.UTF_8);
        this.fileName = fileName;
    }

    private String[] retrieveZoneAwareFileNames() {
        IdentityZone zone = retrieveZone();
        String[] fileNames = new String[2];
        if (zone.isUaa()) {
            fileNames[0] = fileName;
            fileNames[1] = encodedFileName;
        }
        else {
            fileNames[0] = "saml-" + zone.getSubdomain() + "-sp.xml";
            fileNames[1] = URLEncoder.encode(fileNames[0],
                    StandardCharsets.UTF_8);
        }
        return fileNames;
    }
}
