package org.cloudfoundry.identity.uaa.mock.saml;

import java.net.URI;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.junit.jupiter.api.Test;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.xpath;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;

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
                .andExpect(status().isOk());
//            // The SAML SP metadata should match the following UAA configs:
//            // login.entityID
                xml.andExpect(xpath("/EntityDescriptor/@entityID").string(SAML_ENTITY_ID))
                    .andExpect(xpath("/EntityDescriptor/SPSSODescriptor/@AuthnRequestsSigned").booleanValue(true))
                    .andExpect(xpath("/EntityDescriptor/SPSSODescriptor/@WantAssertionsSigned").booleanValue(true));

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
