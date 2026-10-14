package org.cloudfoundry.identity.uaa.mock.clients;

import org.cloudfoundry.identity.uaa.mock.EndpointDocs;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;

import java.util.Map;

import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.certificate1;
import static org.springframework.restdocs.headers.HeaderDocumentation.headerWithName;
import static org.springframework.restdocs.headers.HeaderDocumentation.requestHeaders;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessResponse;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint;
import static org.springframework.restdocs.payload.JsonFieldType.ARRAY;
import static org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@TestPropertySource(properties = "uaa.mtls.enabled=true")
class MtlsTrustBundleEndpointDocs extends EndpointDocs {
    @Autowired
    IdentityZoneProvisioning provisioning;

    @Test
    void listTrustBundleNames() throws Exception {
        IdentityZone zone = provisioning.retrieve(IdentityZone.getUaaZoneId());
        Map<String, String> previous = zone.getConfig().getMtlsTrustBundles();
        zone.getConfig().setMtlsTrustBundles(Map.of("instance-identity", certificate1()));
        identityZoneManager.setCurrentIdentityZone(provisioning.update(zone));
        try {
            String token = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "uaa.admin");
            mockMvc.perform(get("/oauth/mtls/trust-bundles").servletPath("/oauth/mtls/trust-bundles")
                            .header("Authorization", "Bearer " + token))
                    .andExpect(status().isOk())
                    .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()),
                            requestHeaders(headerWithName("Authorization").description(
                                    "Bearer token with clients.read, clients.admin, or zone/UAA admin authority.")),
                            responseFields(fieldWithPath("trust_bundles").type(ARRAY).description(
                                    "Sorted names of CA trust bundles in the current identity zone. PEM contents are never returned."))));
        } finally {
            zone.getConfig().setMtlsTrustBundles(previous);
            provisioning.update(zone);
            identityZoneManager.clear();
        }
    }
}
