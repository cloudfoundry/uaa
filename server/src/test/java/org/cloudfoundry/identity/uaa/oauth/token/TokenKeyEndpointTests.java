package org.cloudfoundry.identity.uaa.oauth.token;

import com.nimbusds.jose.JWSSigner;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.oauth.TokenKeyEndpoint;
import org.cloudfoundry.identity.uaa.oauth.jwt.SignatureVerifier;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.MapCollector;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.security.Principal;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelperX5tTest.CERTIFICATE_1;
import static org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelperX5tTest.SIGNING_KEY_1;
import static org.cloudfoundry.identity.uaa.util.UaaStringUtils.DEFAULT_UAA_URL;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(PollutionPreventionExtension.class)
class TokenKeyEndpointTests {

    private TokenKeyEndpoint tokenKeyEndpoint = new TokenKeyEndpoint(new KeyInfoService("https://localhost.uaa"));
    private Authentication validUaaResource;
    private final String signingKey2 = """
            -----BEGIN RSA PRIVATE KEY-----
            MIIBOQIBAAJBAKIuxhxq0SyeITbTw3SeyHz91eB6xEwRn9PPgl+klu4DRUmVs0h+
            UlVjXSTLiJ3r1bJXVded4JzVvNSh5Nw+7zsCAwEAAQJAYeVH8klL39nHhLfIiHF7
            5W63FhwktyIATrM4KBFKhXn8i29l76qVqX88LAYpeULric8fGgNoSaYVsHWIOgDu
            cQIhAPCJ7hu7OgqvyIGWRp2G2qjKfQVqSntG9HNSt9MhaXKjAiEArJt+PoF0AQFR
            R9O/XULmxR0OUYhkYZTr5eCo7kNscokCIDSv0aLrYKxEkqOn2fHZPv3n1HiiLoxQ
            H20/OhqZ3/IHAiBSn3/31am8zW+l7UM+Fkc29aij+KDsYQfmmvriSp3/2QIgFtiE
            Jkd0KaxkobLdyDrW13QnEaG5TXO0Y85kfu3nP5o=
            -----END RSA PRIVATE KEY-----""";
    private final String signingKey3 = """
            -----BEGIN RSA PRIVATE KEY-----
            MIIBOgIBAAJBAOnndOyLh8axLMyjX+gCglBCeU5Cumjxz9asho5UvO8zf03PWciZ
            DGWce+B+n23E1IXbRKHWckCY0UH7fEgbrKkCAwEAAQJAGR9aCJoH8EhRVn1prKKw
            Wmx5WPWDzgfC2fzXyuvBCzPZNMQqOxWT9ajr+VysuyFZbz+HGJDqpf9Jl+fcIIUJ
            LQIhAPTn319kLU0QzoNBSB53tPhdNbzggBpW/Xv6B52XqGwPAiEA9IAAFu7GVymQ
            /neMHM7/umMFGFFbdq8E2pohLyjcg8cCIQCZWfv/0k2ffQ+jFqSfF1wFTPBSRc1R
            MPlmwSg1oPpANwIgHngBCtqQnvYQGpX9QO3O0oRaczBYTI789Nz2O7FE4asCIGEy
            SkbkWTex/hl+l0wdNErz/yBxP8esbPukOUqks/if
            -----END RSA PRIVATE KEY-----""";

    @BeforeEach
    void setUp() {
        validUaaResource = new UsernamePasswordAuthenticationToken("client_id", null, Collections.singleton(new SimpleGrantedAuthority("uaa.resource")));
    }

    @AfterEach
    void cleanUp() {
        IdentityZoneHolder.clear();
    }

    @Test
    void sharedSecretIsReturnedFromTokenKeyEndpoint() {
        configureKeysForDefaultZone(Collections.singletonMap("someKeyId", "someKey"));
        VerificationKeyResponse response = tokenKeyEndpoint.getKey(validUaaResource);
        assertThat(response.getAlgorithm()).isEqualTo("HS256");
        assertThat(response.getKey()).isEqualTo("someKey");
        assertThat(response.getId()).isEqualTo("someKeyId");
        assertThat(response.getType()).isEqualTo("MAC");
        assertThat(response.getUse().name()).isEqualTo("sig");
    }

    @Test
    void sharedSecretCannotBeAnonymouslyRetrievedFromTokenKeyEndpoint() {
        configureKeysForDefaultZone(Collections.singletonMap("anotherKeyId", "someKey"));

        assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(() -> tokenKeyEndpoint.getKey(
                new AnonymousAuthenticationToken("anon", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"))
        ));
    }

    @Test
    void responseIsBackwardCompatibleWithMap() {
        configureKeysForDefaultZone(Collections.singletonMap("literallyAnything", "someKey"));
        VerificationKeyResponse response = tokenKeyEndpoint.getKey(validUaaResource);

        String serialized = JsonUtils.writeValueAsString(response);

        Map<String, String> deserializedMap = JsonUtils.readValue(serialized, Map.class);
        assertThat(deserializedMap)
                .containsEntry("alg", "HS256")
                .containsEntry("value", "someKey")
                .containsEntry("kty", "MAC")
                .containsEntry("use", "sig");
    }

    @Test
    void keyIsReturnedForZone() {
        createAndSetTestZoneWithKeys(Collections.singletonMap("key1", SIGNING_KEY_1), CERTIFICATE_1);

        VerificationKeyResponse response = tokenKeyEndpoint.getKey(mock(Principal.class));
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        Base64.Decoder decoder = Base64.getUrlDecoder();

        assertThat(encoder.encodeToString(decoder.decode(response.getModulus()))).isEqualTo(response.getModulus());
        assertThat(encoder.encodeToString(decoder.decode((response.getExponent())))).isEqualTo(response.getExponent());

        assertThat(response.getAlgorithm()).isEqualTo("RS256");
        assertThat(response.getId()).isEqualTo("key1");
        assertThat(response.getType()).isEqualTo("RSA");
        assertThat(response.getUse().name()).isEqualTo("sig");
        assertThat(response.getX5t()).isEqualTo("RkckJulawIoaTm0iaziJBwFh7Nc");
    }

    @Test
    void defaultZoneKeyIsReturned_ForZoneWithNoKeys() {
        configureKeysForDefaultZone(Collections.singletonMap("someKeyId", "someKey"));
        createAndSetTestZoneWithKeys(null);

        VerificationKeyResponse response = tokenKeyEndpoint.getKey(validUaaResource);

        assertThat(response.getAlgorithm()).isEqualTo("HS256");
        assertThat(response.getKey()).isEqualTo("someKey");
        assertThat(response.getId()).isEqualTo("someKeyId");
        assertThat(response.getType()).isEqualTo("MAC");
        assertThat(response.getUse().name()).isEqualTo("sig");
    }

    @Test
    void listResponseContainsAllPublicKeysWhenUnauthenticated() {
        Map<String, String> keysForUaaZone = new HashMap<>();
        keysForUaaZone.put("RsaKey1", SIGNING_KEY_1);
        keysForUaaZone.put("thisIsASymmetricKeyThatShouldNotShowUp", "ItHasSomeTextThatIsNotPEM");
        keysForUaaZone.put("RsaKey2", signingKey2);
        keysForUaaZone.put("RsaKey3", signingKey3);
        configureKeysForDefaultZone(keysForUaaZone);

        VerificationKeysListResponse keysResponse = tokenKeyEndpoint.getKeys(null);
        List<VerificationKeyResponse> keys = keysResponse.getKeys();
        List<String> keyIds = keys.stream().map(VerificationKeyResponse::getId).toList();
        assertThat(keyIds).containsExactlyInAnyOrder("RsaKey1", "RsaKey2", "RsaKey3");

        HashMap<String, VerificationKeyResponse> keysMap = keys.stream().collect(new MapCollector<>(VerificationKeyResponse::getId, k -> k));
        VerificationKeyResponse key1Response = keysMap.get("RsaKey1");
        VerificationKeyResponse key2Response = keysMap.get("RsaKey2");
        VerificationKeyResponse key3Response = keysMap.get("RsaKey3");

        byte[] bytes = "Text for testing of private/public key match".getBytes();
        JWSSigner rsaSigner = new KeyInfo("RsaKey1", SIGNING_KEY_1, DEFAULT_UAA_URL).getSigner();
        SignatureVerifier rsaVerifier = new KeyInfo("RsaKey1", SIGNING_KEY_1, DEFAULT_UAA_URL).getVerifier();

        rsaSigner = new KeyInfo("RsaKey2", signingKey2, DEFAULT_UAA_URL).getSigner();
        rsaVerifier = new KeyInfo("RsaKey2", signingKey2, DEFAULT_UAA_URL).getVerifier();

        rsaSigner = new KeyInfo("RsaKey3", signingKey3, DEFAULT_UAA_URL).getSigner();
        rsaVerifier = new KeyInfo("RsaKey3", signingKey3, DEFAULT_UAA_URL).getVerifier();

        //ensure that none of the keys are padded
        keys.forEach(
                key ->
                        assertThat(key.getExponent().endsWith("=") ||
                                key.getModulus().endsWith("=")).as("Invalid padding for key:" + key.getKid()).isFalse()
        );
    }

    @Test
    void listResponseContainsAllKeysWhenAuthenticated() {
        Map<String, String> keysForUaaZone = new HashMap<>();
        keysForUaaZone.put("RsaKey1", SIGNING_KEY_1);
        keysForUaaZone.put("RsaKey2", signingKey2);
        keysForUaaZone.put("RsaKey3", signingKey3);
        keysForUaaZone.put("SymmetricKey", "ItHasSomeTextThatIsNotPEM");
        configureKeysForDefaultZone(keysForUaaZone);

        VerificationKeysListResponse keysResponse = tokenKeyEndpoint.getKeys(validUaaResource);
        List<VerificationKeyResponse> keys = keysResponse.getKeys();
        List<String> keyIds = keys.stream().map(VerificationKeyResponse::getId).toList();
        assertThat(keyIds).containsExactlyInAnyOrder("RsaKey1", "RsaKey2", "RsaKey3", "SymmetricKey");

        VerificationKeyResponse symKeyResponse = keys.stream().filter(k -> "SymmetricKey".equals(k.getId())).findAny().get();
        assertThat(symKeyResponse.getKey()).isEqualTo("ItHasSomeTextThatIsNotPEM");
    }

    @Test
    void tokenKeyEndpoint_ReturnsAllKeysForZone() {
        Map<String, String> keys = new HashMap<>();
        keys.put("key1", SIGNING_KEY_1);
        keys.put("key2", signingKey2);
        createAndSetTestZoneWithKeys(keys);

        VerificationKeysListResponse keysResponse = tokenKeyEndpoint.getKeys(mock(Principal.class));
        List<VerificationKeyResponse> keysForZone = keysResponse.getKeys();
        List<String> keyIds = keysForZone.stream().map(VerificationKeyResponse::getId).toList();
        assertThat(keyIds).containsExactlyInAnyOrder("key1", "key2");
    }

    @Test
    void responseHeaderIncludesEtag() {
        createAndSetTestZoneWithKeys(Collections.singletonMap("key1", SIGNING_KEY_1));

        ResponseEntity<VerificationKeyResponse> keyResponse = tokenKeyEndpoint.getKey(mock(Principal.class), "NaN");
        HttpHeaders headers = keyResponse.getHeaders();
        assertThat(headers.get("ETag")).isNotNull();

        ResponseEntity<VerificationKeysListResponse> keysResponse = tokenKeyEndpoint.getKeys(mock(Principal.class), "NaN");
        headers = keysResponse.getHeaders();
        assertThat(headers.get("ETag")).isNotNull();
    }

    @Test
    void returns304IfUnmodified() {
        IdentityZone zone = createAndSetTestZoneWithKeys(null);

        String lastModified = String.valueOf(zone.getLastModified().getTime());

        ResponseEntity<VerificationKeyResponse> keyResponse = tokenKeyEndpoint.getKey(mock(Principal.class), lastModified);
        assertThat(keyResponse.getStatusCode()).isEqualTo(HttpStatus.NOT_MODIFIED);

        ResponseEntity<VerificationKeysListResponse> keysResponse = tokenKeyEndpoint.getKeys(mock(Principal.class), lastModified);
        assertThat(keysResponse.getStatusCode()).isEqualTo(HttpStatus.NOT_MODIFIED);
    }

    private IdentityZone createAndSetTestZoneWithKeys(Map<String, String> keys) {
        return createAndSetTestZoneWithKeys(keys, null);
    }

    private IdentityZone createAndSetTestZoneWithKeys(Map<String, String> keys, String cert) {
        IdentityZone zone = MultitenancyFixture.identityZone("test-zone", "test");
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        TokenPolicy tokenPolicy = new TokenPolicy();
        Map<String, TokenPolicy.KeyInformation> keyInformationMap = Optional.ofNullable(keys).filter(Objects::nonNull).orElse(new HashMap<>())
                .entrySet().stream().filter(Objects::nonNull).collect(Collectors.toMap(Map.Entry::getKey, e -> {
                    TokenPolicy.KeyInformation keyInfo = new TokenPolicy.KeyInformation();
                    keyInfo.setSigningKey(e.getValue());
                    keyInfo.setSigningCert(cert);
                    return keyInfo;
                }));
        tokenPolicy.setKeyInformation(keyInformationMap);
        config.setTokenPolicy(tokenPolicy);
        zone.setConfig(config);
        IdentityZoneHolder.set(zone);

        return zone;
    }

    private void configureKeysForDefaultZone(Map<String, String> keys) {
        IdentityZoneProvisioning provisioning = mock(IdentityZoneProvisioning.class);
        IdentityZoneHolder.setProvisioning(provisioning);
        IdentityZone zone = IdentityZone.getUaa();
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        TokenPolicy tokenPolicy = new TokenPolicy();
        tokenPolicy.setKeys(keys);
        config.setTokenPolicy(tokenPolicy);
        zone.setConfig(config);
        when(provisioning.retrieve("uaa")).thenReturn(zone);
    }
}
