package org.cloudfoundry.identity.uaa.mock.saml;

import java.net.URI;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
//import org.junit.jupiter.api.Disabled;
import org.junit.Assert;
import org.junit.jupiter.api.Test;

import static java.util.function.Predicate.not;
//import static org.hamcrest.Matchers.emptyOrNullString;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.text.IsEmptyString.emptyOrNullString;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.xpath;

@DefaultTestContext
class SamlMetadataMockMvcTests {

    @Autowired
    private MockMvc mockMvc;


    @Test
    void redirectFromMetadataRoot() throws Exception {
        ResultActions xml = mockMvc.perform(get(new URI("/saml/metadata")))
                .andExpect(forwardedUrl("/saml/metadata/example"));
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
//    @Disabled("Returning a 404, but it curls 200 and payload look good. It should not be a forwardedURL but direct")
    void testSamlMetadataDefault() throws Exception {
        ResultActions response = null;

        ResultActions xml = mockMvc.perform(get(new URI("/saml/metadata/example")))
                .andExpect(status().isOk());
//                .andExpect(content().string(not(emptyOrNullString())))
                String metadataXml = xml.andReturn().getResponse().getContentAsString();

//                .andExpect(xpath("/md:EntityDescriptor/@entityID").string("cloudfoundry-saml-login"));



//            xpath("...ds:DigestMethod/@Algorithm").string("http://www.w3.org/2001/04/xmlenc#sha256");

//            String metadataXml = (String)response.getBody();
//
//            // The SAML SP metadata should match the following UAA configs:
//            // login.entityID
            Assert.assertThat(metadataXml, containsString(
                    "entityID=\"cloudfoundry-saml-login\""));
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
