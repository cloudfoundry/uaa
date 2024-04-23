package org.cloudfoundry.identity.uaa.mock.saml;

import java.net.URI;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@DefaultTestContext
class SamlMetadataMockMvcTests {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void legacyMetadataRoot() throws Exception {
        mockMvc.perform(get(new URI("/saml/metadata")))
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

        mockMvc.perform(get(new URI("/saml/metadata/example")))
                .andDo(print())
                .andExpectAll(
                        status().isOk(),
                        header().string(HttpHeaders.CONTENT_DISPOSITION, containsString("filename=\"saml-sp-metadata.xml\";")),
                        xpath("/EntityDescriptor/@entityID").string("integration-saml-entity-id"), // matches UAA config login.entityID
                        xpath("/EntityDescriptor/SPSSODescriptor/@AuthnRequestsSigned").booleanValue(true), // matches UAA config login.saml.signRequest
                        xpath("/EntityDescriptor/SPSSODescriptor/@WantAssertionsSigned").booleanValue(true),
                        xpath("/EntityDescriptor/SPSSODescriptor/NameIDFormat").string("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")  // matches UAA config login.saml.NameID
                );
    }

    @Nested
    @DefaultTestContext
    @TestPropertySource(properties = "login.saml.signRequest = false")
    class SamlMetadataAlternativeConfigsMockMvcTests {
        @Autowired
        private MockMvc mockMvc;

        @Test
        void testSamlMetadataAuthnRequestsSignedIsFalse() throws Exception {
            mockMvc.perform(get(new URI("/saml/metadata/example")))
                    .andDo(print())
                    .andExpectAll(
                            status().isOk(),
                            header().string(HttpHeaders.CONTENT_DISPOSITION, containsString("filename=\"saml-sp-metadata.xml\";")),
                            xpath("/EntityDescriptor/SPSSODescriptor/@AuthnRequestsSigned").booleanValue(false), // matches UAA config login.saml.signRequest
                            xpath("/EntityDescriptor/SPSSODescriptor/@WantAssertionsSigned").booleanValue(true)
                    );
        }
    }
}