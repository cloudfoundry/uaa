package org.cloudfoundry.identity.uaa.provider.saml;


import org.cloudfoundry.identity.uaa.provider.saml.SamlRelyingPartyRegistrationRepository;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.impl.IDPSSODescriptorBuilder;
import org.opensaml.xmlsec.signature.XMLSignatureBuilder;
import org.opensaml.xmlsec.signature.impl.SignatureImpl;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
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
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.List;
import java.util.function.Consumer;

import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.xmlsec.signature.Signature;



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
            spssodescriptor.setAuthnRequestsSigned(entityDescriptorParameters.getRelyingPartyRegistration().getAssertingPartyDetails().getWantAuthnRequestsSigned()); // need to read from `saml.signRequest` eventually
//            try {
//                XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM", "XMLDSig");
//                CanonicalizationMethod c14nMethod = xmlSignatureFactory.newCanonicalizationMethod("http://www.w3.org/2001/10/xml-exc-c14n#", null);
//                DigestMethod digestMethod = xmlSignatureFactory.newDigestMethod("http://www.w3.org/2001/04/xmlenc#sha256", null);
//                SignatureMethod signMethod = xmlSignatureFactory.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", null);
//
//                List<Transform> transforms = List.of(
//                        xmlSignatureFactory.newTransform("http://www.w3.org/2000/09/xmldsig#enveloped-signature", null),
//                        xmlSignatureFactory.newTransform("http://www.w3.org/2001/10/xml-exc-c14n#", null)
//                );
//
//                Reference referenceDoc = xmlSignatureFactory.newReference("", digestMethod, transforms, null, null);
//                List<Reference> references = List.of(referenceDoc);
//
//                SignedInfo signedInfo = xmlSignatureFactory.newSignedInfo(c14nMethod, signMethod, references);
//                KeyInfo keyInfo = createKeyInfo(xmlSignatureFactory);
//                XMLSignature xmlSignature = xmlSignatureFactory.newXMLSignature(signedInfo, keyInfo, null, null, null);
//
//
//            } catch (NoSuchProviderException e) {
//                throw new RuntimeException(e);
//            } catch (InvalidAlgorithmParameterException e) {
//                throw new RuntimeException(e);
//            } catch (NoSuchAlgorithmException e) {
//                throw new RuntimeException(e);
//            }
////            XMLSignatureBuilder xmlSigBuilder = new XMLSignatureBuilder

//            descriptor.setSignature(Signature new Signature());

//            Signature signature = new SignatureImpl(SignatureConstants.XMLSIG_NS); //, "localName", "ds");
//            Signature signature = descriptor.getSignature();
//            signature.setSchemaLocation(SignatureConstants.XMLSIG_NS);
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