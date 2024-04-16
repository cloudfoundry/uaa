package org.cloudfoundry.identity.uaa.provider.saml;


import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.metadata.Saml2MetadataResolver;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

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

    public SamlMetadataEndpoint(
            RelyingPartyRegistrationRepository relyingPartyRegistrationRepository

    ) {
        Assert.notNull(relyingPartyRegistrationRepository, "relyingPartyRegistrationRepository cannot be null");
        this.relyingPartyRegistrationResolver = new DefaultRelyingPartyRegistrationResolver(relyingPartyRegistrationRepository);
        this.saml2MetadataResolver = new OpenSamlMetadataResolver();
        setFileName(DEFAULT_FILE_NAME);
    }

    @GetMapping(value = "/saml/metadata", produces = APPLICATION_XML_CHARSET_UTF_8)
    @ResponseBody
    public ResponseEntity<String> legacyMetadataEndpoint(HttpServletRequest request) {
        return metadataEndpoint(DEFAULT_REGISTRATION_ID, request);
    }

    @GetMapping(value = "/saml/metadata/{registrationId}", produces = APPLICATION_XML_CHARSET_UTF_8)
    @ResponseBody
    public ResponseEntity<String> metadataEndpoint(@PathVariable String registrationId,
                                                   HttpServletRequest request
                                                   //, HttpServletResponse response

    ) {

        String format = "attachment; filename=\"%s\"; filename*=UTF-8''%s";

        RelyingPartyRegistration relyingPartyRegistration =
                this.relyingPartyRegistrationResolver.resolve(request,registrationId);
        if (relyingPartyRegistration == null) {
            return ResponseEntity.status(HttpServletResponse.SC_UNAUTHORIZED).build();
        }
        String metadata = this.saml2MetadataResolver.resolve(relyingPartyRegistration);

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
