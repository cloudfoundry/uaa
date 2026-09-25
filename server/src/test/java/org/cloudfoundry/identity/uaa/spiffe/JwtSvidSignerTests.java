package org.cloudfoundry.identity.uaa.spiffe;

import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.oauth.TokenEndpointBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwtSvidSignerTests {

    private KeyPair signingKeyPair;
    private JwtSvidSigner signer;

    @BeforeEach
    void setUp() {
        signingKeyPair = SpiffeTestCerts.newRsaKeyPair();
        String pem = SpiffeTestCerts.pkcs8PrivateKeyPem(signingKeyPair.getPrivate());
        KeyInfo keyInfo = new KeyInfo("svid-key", pem, "https://uaa.example.com");

        KeyInfoService keyInfoService = mock(KeyInfoService.class);
        when(keyInfoService.getActiveKey()).thenReturn(keyInfo);

        TokenEndpointBuilder tokenEndpointBuilder = mock(TokenEndpointBuilder.class);
        when(tokenEndpointBuilder.getTokenEndpoint(any()))
                .thenReturn("https://uaa.example.com/oauth/token");

        SpiffeProperties props = new SpiffeProperties("example.org", "ca", 900L, 60, true);
        signer = new JwtSvidSigner(keyInfoService, tokenEndpointBuilder, props);
    }

    @Test
    void signsVerifiableJwtSvidWithExpectedClaims() throws Exception {
        CfInstanceIdentity identity = new CfInstanceIdentity("org-1", "space-2", "app-3");
        String spiffeId = "spiffe://example.org/cf/org/org-1/space/space-2/app/app-3/process/web";
        long before = Instant.now().getEpochSecond();

        JwtSvidSigner.JwtSvidResult result =
                signer.sign(spiffeId, identity, "web", "https://api.example.com");

        SignedJWT jwt = SignedJWT.parse(result.svid());

        // Header references UAA's key + JWKS URL so relying parties can fetch the key.
        assertThat(jwt.getHeader().getKeyID()).isEqualTo("svid-key");
        assertThat(jwt.getHeader().getAlgorithm().getName()).isEqualTo("RS256");

        // Signature verifies against the signing key's public half.
        assertThat(jwt.verify(new RSASSAVerifier((RSAPublicKey) signingKeyPair.getPublic()))).isTrue();

        var claims = jwt.getJWTClaimsSet();
        assertThat(claims.getIssuer()).isEqualTo("https://uaa.example.com/oauth/token");
        assertThat(claims.getSubject()).isEqualTo(spiffeId);
        assertThat(claims.getAudience()).containsExactly("https://api.example.com");
        assertThat(claims.getJWTID()).isNotBlank();
        assertThat(claims.getExpirationTime().toInstant().getEpochSecond())
                .isBetween(before + 899, before + 902);

        @SuppressWarnings("unchecked")
        Map<String, Object> cf = (Map<String, Object>) claims.getClaim("cf");
        assertThat(cf).containsEntry("org_id", "org-1")
                .containsEntry("space_id", "space-2")
                .containsEntry("app_id", "app-3")
                .containsEntry("process_type", "web");

        assertThat(result.spiffeId()).isEqualTo(spiffeId);
        assertThat(result.expiresAt()).isEqualTo(claims.getExpirationTime().toInstant().getEpochSecond());
        assertThat((List<?>) claims.getAudience()).hasSize(1);
    }
}
