package org.cloudfoundry.identity.uaa.spiffe;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.security.cert.X509Certificate;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class JwtSvidControllerTests {

    private final CertificateOuParser ouParser = mock(CertificateOuParser.class);
    private final InstanceIdentityVerifier identityVerifier = mock(InstanceIdentityVerifier.class);
    private final ProofOfPossessionVerifier popVerifier = mock(ProofOfPossessionVerifier.class);
    private final JwtSvidSigner signer = mock(JwtSvidSigner.class);
    private final SpiffeProperties props = new SpiffeProperties("example.org", "ca", 900L, 60, true);

    private MockMvc mockMvc;
    private final ObjectMapper objectMapper = new ObjectMapper();

    // The controller parses the PEM with the real KeyWithCert BEFORE any mocked
    // collaborator runs, so this must be a genuinely parseable certificate. The OUs
    // are irrelevant here because CertificateOuParser is mocked.
    private static final String CERT_PEM = SpiffeTestCerts.certificatePem(
            SpiffeTestCerts.newInstanceCert(SpiffeTestCerts.newCa(), "org-1", "space-2", "app-3")
                    .certificate());

    @BeforeEach
    void setUp() {
        JwtSvidController controller =
                new JwtSvidController(ouParser, identityVerifier, popVerifier, signer, props);
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new JwtSvidController.ExceptionHandling())
                .build();
    }

    private String body(String popSignature) throws Exception {
        return objectMapper.writeValueAsString(
                new JwtSvidRequest(CERT_PEM, "web", "https://api.example.com", 1000L, popSignature));
    }

    @Test
    void returnsSignedSvidOnHappyPath() throws Exception {
        CfInstanceIdentity identity = new CfInstanceIdentity("org-1", "space-2", "app-3");
        String spiffeId = "spiffe://example.org/cf/org/org-1/space/space-2/app/app-3/process/web";
        when(ouParser.parse(any())).thenReturn(identity);
        when(popVerifier.isValid(any(), eq(spiffeId), eq("https://api.example.com"), anyLong(), anyString()))
                .thenReturn(true);
        when(signer.sign(eq(spiffeId), eq(identity), eq("web"), eq("https://api.example.com")))
                .thenReturn(new JwtSvidSigner.JwtSvidResult("header.body.sig", spiffeId, 1900L));

        mockMvc.perform(post("/jwt-svid/sign")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("c2ln")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.svid").value("header.body.sig"))
                .andExpect(jsonPath("$.spiffe_id").value(spiffeId))
                .andExpect(jsonPath("$.expires_at").value(1900));
    }

    @Test
    void returns401WhenCertificateUntrusted() throws Exception {
        when(ouParser.parse(any())).thenReturn(new CfInstanceIdentity("o", "s", "a"));
        org.mockito.Mockito.doThrow(
                        new InstanceIdentityVerifier.InvalidInstanceCertificateException("bad", null))
                .when(identityVerifier).verify(any(X509Certificate.class));

        mockMvc.perform(post("/jwt-svid/sign")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("c2ln")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void returns401WhenProofOfPossessionFails() throws Exception {
        when(ouParser.parse(any())).thenReturn(new CfInstanceIdentity("org-1", "space-2", "app-3"));
        when(popVerifier.isValid(any(), anyString(), anyString(), anyLong(), anyString())).thenReturn(false);

        mockMvc.perform(post("/jwt-svid/sign")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("c2ln")))
                .andExpect(status().isUnauthorized());
    }

    /**
     * The controller must reject structurally dangerous inputs BEFORE they reach
     * {@link SpiffeId#format} (process_type is concatenated into the SPIFFE ID path)
     * or the proof-of-possession message (newlines would make the signed message
     * ambiguous). All rejections are 400 Bad Request.
     */
    @Nested
    class InputValidation {

        @BeforeEach
        void stubCollaboratorsSoOnlyValidationCanReject() {
            // A valid identity keeps the pre-validation flow deterministic: without the
            // new guard the request would reach the (unstubbed -> false) PoP check and
            // return 401, so a 400 can only come from input validation.
            when(ouParser.parse(any())).thenReturn(new CfInstanceIdentity("org-1", "space-2", "app-3"));
        }

        @ParameterizedTest
        @ValueSource(strings = {"web/extra", "with space", "dotted.type", "semi;colon", "comma,type", "star*"})
        void rejectsProcessTypeWithIllegalCharacters(String processType) throws Exception {
            mockMvc.perform(post("/jwt-svid/sign")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(requestBody(processType, "https://api.example.com")))
                    .andExpect(status().isBadRequest());
        }

        @Test
        void rejectsProcessTypeWithControlCharacter() throws Exception {
            mockMvc.perform(post("/jwt-svid/sign")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(requestBody("web\ninjected", "https://api.example.com")))
                    .andExpect(status().isBadRequest());
        }

        @Test
        void rejectsEmptyProcessType() throws Exception {
            mockMvc.perform(post("/jwt-svid/sign")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(requestBody("", "https://api.example.com")))
                    .andExpect(status().isBadRequest());
        }

        @Test
        void rejectsOverlongProcessType() throws Exception {
            mockMvc.perform(post("/jwt-svid/sign")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(requestBody("a".repeat(64), "https://api.example.com")))
                    .andExpect(status().isBadRequest());
        }

        @Test
        void rejectsBlankAudience() throws Exception {
            mockMvc.perform(post("/jwt-svid/sign")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(requestBody("web", "   ")))
                    .andExpect(status().isBadRequest());
        }

        @Test
        void rejectsAudienceWithControlCharacter() throws Exception {
            mockMvc.perform(post("/jwt-svid/sign")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(requestBody("web", "https://api.example.com\nHeader: injected")))
                    .andExpect(status().isBadRequest());
        }

        @Test
        void rejectsOverlongAudience() throws Exception {
            mockMvc.perform(post("/jwt-svid/sign")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(requestBody("web", "https://" + "a".repeat(512))))
                    .andExpect(status().isBadRequest());
        }

        @Test
        void rejectsMalformedCertificatePem() throws Exception {
            // process_type/audience are valid, so the unreadable PEM is what produces the 400.
            String requestWithBadCert = objectMapper.writeValueAsString(
                    new JwtSvidRequest("not-a-pem", "web", "https://api.example.com", 1000L, "c2ln"));
            mockMvc.perform(post("/jwt-svid/sign")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(requestWithBadCert))
                    .andExpect(status().isBadRequest());
        }

        private String requestBody(String processType, String audience) throws Exception {
            return objectMapper.writeValueAsString(
                    new JwtSvidRequest(CERT_PEM, processType, audience, 1000L, "c2ln"));
        }
    }
}
