package org.cloudfoundry.identity.uaa.provider.saml;


import org.cloudfoundry.identity.uaa.provider.saml.SamlRelyingPartyRegistrationRepository;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.impl.IDPSSODescriptorBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.metadata.Saml2MetadataResolver;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.function.Consumer;

import org.opensaml.saml.saml2.metadata.SPSSODescriptor;



@Controller
public class SamlMetadataEndpoint {
    private static final String DEFAULT_REGISTRATION_ID = "example";
    private static final String DEFAULT_FILE_NAME = "saml-sp-metadata.xml";
    public static final String APPLICATION_XML_CHARSET_UTF_8 = "application/xml; charset=UTF-8";
    /*
     * @todo - this should be a Zone aware resolver
     */
    private final RelyingPartyRegistrationResolver relyingPartyRegistrationResolver;
    private final Saml2MetadataResolver saml2MetadataResolver;

    private String fileName;
    private String encodedFileName;

    private class EntityDescriptorCustomizer implements Consumer<OpenSamlMetadataResolver.EntityDescriptorParameters> {

        @Override
        public void accept(OpenSamlMetadataResolver.EntityDescriptorParameters entityDescriptorParameters) {
            EntityDescriptor descriptor = entityDescriptorParameters.getEntityDescriptor();
            SPSSODescriptor spssodescriptor = descriptor.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
            spssodescriptor.setWantAssertionsSigned(true);
            spssodescriptor.setAuthnRequestsSigned(true);
        }
    }

    public SamlMetadataEndpoint(
            RelyingPartyRegistrationRepository relyingPartyRegistrationRepository

    ) {
        Assert.notNull(relyingPartyRegistrationRepository, "relyingPartyRegistrationRepository cannot be null");
        this.relyingPartyRegistrationResolver = new DefaultRelyingPartyRegistrationResolver(relyingPartyRegistrationRepository);
        OpenSamlMetadataResolver resolver = new OpenSamlMetadataResolver();
        this.saml2MetadataResolver = resolver;
        resolver.setEntityDescriptorCustomizer(new EntityDescriptorCustomizer());
        setFileName(DEFAULT_FILE_NAME);
    }

    @GetMapping(value = "/saml/metadata", produces = APPLICATION_XML_CHARSET_UTF_8)
    @ResponseBody
    public ResponseEntity<String> legacyMetadataEndpoint(HttpServletRequest request) {
        return metadataEndpoint(DEFAULT_REGISTRATION_ID, request);
    }

    @Autowired
    private RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

    @GetMapping(value = "/saml/metadata/{registrationId}", produces = APPLICATION_XML_CHARSET_UTF_8)
    @ResponseBody
    public ResponseEntity<String> metadataEndpoint(@PathVariable String registrationId,
                                                   HttpServletRequest request
                                                   //, HttpServletResponse response

    ) {

//        String format = "attachment; filename=\"%s\"; filename*=UTF-8''%s";
        String format = "attachment; filename=\"%s\"; filename*=UTF-8";

//        RelyingPartyRegistration relyingPartyRegistration =
//                this.relyingPartyRegistrationResolver.resolve(request,registrationId);
        RelyingPartyRegistration relyingPartyRegistration = relyingPartyRegistrationRepository.findByRegistrationId(registrationId);
        if (relyingPartyRegistration == null) {
            return ResponseEntity.status(HttpServletResponse.SC_UNAUTHORIZED).build();
        }
        String metadata = this.saml2MetadataResolver.resolve(relyingPartyRegistration);

        /*
         * @todo - fileName may need to be dynamic based on registrationID
        */

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, String.format(format, fileName, encodedFileName))
                .body(metadata);
    }

    public void setFileName(String fileName) {
        try {
            this.encodedFileName = URLEncoder.encode(fileName, StandardCharsets.UTF_8.name());
            this.fileName = fileName;
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }
}