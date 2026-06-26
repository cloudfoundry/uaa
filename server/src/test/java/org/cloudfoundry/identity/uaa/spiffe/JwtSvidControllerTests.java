package org.cloudfoundry.identity.uaa.spiffe;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
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
}
