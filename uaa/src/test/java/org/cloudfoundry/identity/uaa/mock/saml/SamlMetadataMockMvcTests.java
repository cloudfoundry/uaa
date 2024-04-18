package org.cloudfoundry.identity.uaa.mock.saml;

import java.net.URI;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.junit.jupiter.api.Test;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@DefaultTestContext
class SamlMetadataMockMvcTests {

    public static final String SAML_ENTITY_ID = "integration-saml-entity-id";
    @Autowired
    private MockMvc mockMvc;


    @Test
    void legacyMetadataRoot() throws Exception {
        ResultActions xml = mockMvc.perform(get(new URI("/saml/metadata")))
                .andExpect(forwardedUrl("/saml/metadata/example"));
    }

    @Test
    void testSamlMetadataRootNoEndingSlash() throws Exception {
        mockMvc.perform(get(new URI("/saml/metadata")))
                .andExpect(status().isOk());
    }

    @Test
    void testSamlMetadataRootWithEndingSlash() throws Exception {
        mockMvc.perform(get(new URI("/saml/metadata/")))
                .andExpect(status().isOk());
    }


    @Test
    void testSamlMetadataDefaultNoEndingSlash() throws Exception {
        mockMvc.perform(get(new URI("/saml/metadata/example")))
                .andExpect(status().isOk());
    }

    @Test
    void testSamlMetadataDefaultWithEndingSlash() throws Exception {
        mockMvc.perform(get(new URI("/saml/metadata/example/")))
                .andExpect(status().isOk());
    }

    @Test
    void testSamlMetadataXMLValidation() throws Exception {
        ResultActions response = null;

        ResultActions xml = mockMvc.perform(get(new URI("/saml/metadata/example")))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.CONTENT_DISPOSITION, containsString("filename=\"saml-sp-metadata.xml\";")));
//                .andExpect(header().string(HttpHeaders.CONTENT_DISPOSITION, containsString("filename=\"saml-sp-metadata.xml\";"))); // Need to cover all the content-disposition entries
//                .andExpect(header().string(HttpHeaders.CONTENT_DISPOSITION, containsString("filename=\"saml-sp-metadata.xml\";")));// Need to cover all the content-disposition entries

//            // The SAML SP metadata should match the following UAA configs:
//            // login.entityID
                xml.andExpect(xpath("/EntityDescriptor/@entityID").string(SAML_ENTITY_ID))
                    .andExpect(xpath("/EntityDescriptor/SPSSODescriptor/@AuthnRequestsSigned").booleanValue(true))
                    .andExpect(xpath("/EntityDescriptor/SPSSODescriptor/@WantAssertionsSigned").booleanValue(true))
                    .andExpect(xpath("/EntityDescriptor/Signature/@xmlns:ds").string("http://www.w3.org/2000/09/xmldsig#")) // signatureConstaints
                    .andExpect(xpath("/EntityDescriptor/SignedInfo/SignatureMethod/@Algorithm").string("http://www.w3.org/2000/09/xmldsig#rsa-sha1")); // Always SHA1? no

//            xpath("...ds:DigestMethod/@Algorithm").string("http://www.w3.org/2001/04/xmlenc#sha256");

//            String metadataXml = (String)response.getBody();
//
//            Assert.assertThat(metadataXml, containsString(
//                    "entityID=\"integration-saml-entity-id\""));
//            // login.saml.signatureAlgorithm
//            Assert.assertThat(metadataXml, containsString(
//                    "<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>"));
//            Assert.assertThat(metadataXml, containsString(
//                    "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>"));
//            // login.saml.signRequest
//            Assert.assertThat(metadataXml, containsString("AuthnRequestsSigned=\"true\""));
//            // login.saml.wantAssertionSigned
//            Assert.assertThat(metadataXml, containsString(
//                    "WantAssertionsSigned=\"true\""));
//            // login.saml.nameID
//            Assert.assertThat(metadataXml, containsString(
//                    "<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>"));

    }
}
