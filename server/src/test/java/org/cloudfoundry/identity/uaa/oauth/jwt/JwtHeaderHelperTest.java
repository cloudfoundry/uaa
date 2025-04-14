package org.cloudfoundry.identity.uaa.oauth.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.cloudfoundry.identity.uaa.test.RandomParametersJunitExtension;
import org.cloudfoundry.identity.uaa.test.RandomParametersJunitExtension.RandomValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

@Tag("https://tools.ietf.org/html/rfc7519#section-5")
@DisplayName("JOSE Header")
@ExtendWith(RandomParametersJunitExtension.class)
class JwtHeaderHelperTest {

    @Tag("https://tools.ietf.org/html/rfc7519#ref-JWS")
    @DisplayName("JWS")
    @Nested
    class JWS {
        ObjectNode objectNode;

        @BeforeEach
        void setup() {
            objectNode = new ObjectMapper().createObjectNode();
            objectNode.put("kid", "key-id");
            objectNode.put("alg", "key-alg");
            objectNode.put("enc", "key-encoding");
            objectNode.put("iv", "key-init-vector");
            objectNode.put("typ", "JWT");
        }

        @DisplayName("given a valid JOSE header it should deserialize without error")
        @Test
        void shouldDeserializeWithValidHeaders() {
            JwtHeader header = JwtHeaderHelper.create(asBase64(objectNode.toString()));

            validateJwtHeaders(header);
        }

        @Test
        void createFromStringThrowsExceptionWhenTypeIsNotJWT() {
            objectNode.put("typ", "NOT-JWT");

            assertThatThrownBy(() -> JwtHeaderHelper.create(asBase64(objectNode.toString())))
                    .isInstanceOf(Exception.class)
                    .hasMessageContaining("typ is not \"JWT\"");
        }

        @DisplayName("given a valid signer it should serialize without error")
        @Test
        void shouldSerializeWithValidSigner() {
            final CommonSigner hmac = new CommonSigner("fake-key", "HMAC", null);

            JwtHeader header = JwtHeaderHelper.create(hmac.algorithm(), hmac.keyId(), hmac.keyURL());

            assertThat(header.parameters.typ).isEqualTo("JWT");
            assertThat(header.parameters.kid).isEqualTo("fake-key");
            assertThat(header.parameters.alg).isEqualTo("HS256");
            assertThat(header.parameters.enc).isNull();
            assertThat(header.parameters.iv).isNull();
        }

        @ParameterizedTest
        @ValueSource(strings = {"JWT", "jwt"})
        void canDeserializeCtyHeader(String validCty) {
            objectNode.put("cty", validCty);

            JwtHeader header = JwtHeaderHelper.create(asBase64(objectNode.toString()));

            assertThat(header.parameters.cty).isEqualTo(validCty);
        }

        @Tag("https://tools.ietf.org/html/rfc7515#section-4")
        @Test
        void shouldIgnoreAnyNonUnderstoodHeaders(@RandomValue String randomVal) {
            objectNode.put(randomVal, randomVal);
            JwtHeader header = JwtHeaderHelper.create(asBase64(objectNode.toString()));
            validateJwtHeaders(header);
        }

        @Tag("https://tools.ietf.org/html/rfc7516#section-4.1.2")
        @DisplayName("the enc/iv header claims are for JWE tokens.")
        @Test
        void shouldSerializeOnlyWithValidRequiredHeaders() {
            final CommonSigner hmac = new CommonSigner("fake-key", "HMAC", null);
            JwtHeader header = JwtHeaderHelper.create(hmac.algorithm(), hmac.keyId(), hmac.keyURL());

            assertThat(header.toString()).doesNotContain("enc")
                    .doesNotContain("iv")
                    .doesNotContain("jwk")
                    .doesNotContain("x5u")
                    .doesNotContain("x5c")
                    .doesNotContain("x5t")
                    .doesNotContain("x5t#S256")
                    .doesNotContain("crit")
                    // support not including `cty` if not present for back-compat
                    .doesNotContain("cty");
        }

        @DisplayName("Optional headers from JWS spec")
        @Nested
        class OptionalHeaders {
            @BeforeEach
            void setup() {
                objectNode = new ObjectMapper().createObjectNode();
            }

            @ParameterizedTest
            @ValueSource(strings = {"JWT", "jwt"})
            void shouldAllowTypHeader(String validTyp) {
                objectNode.put("alg", "RS256");
                objectNode.put("typ", validTyp);

                JwtHeader header = JwtHeaderHelper.create(asBase64(objectNode.toString()));

                assertThat(header.parameters.typ).isEqualTo(validTyp);
            }

            @DisplayName("should deserialize when provided optional enc/iv claims. " +
                    "enc/iv are *not* claims that belong to the JWS header. " +
                    "But for now we will allow tokens that contain these claims for backwards compatibility")
            @Test
            void shouldAllowEncAndIvHeaders(@RandomValue String validEnc, @RandomValue String validIv) {
                objectNode.put("enc", validEnc);
                objectNode.put("iv", validIv);

                JwtHeaderHelper.create(asBase64(objectNode.toString()));
            }

            @Test
            void shouldAllowJwkHeader() {
                objectNode.put("alg", "RS256");
                objectNode.putObject("jwk").put("kty", "RSA").put("e", "e").put("n", "n");

                JwtHeader header = JwtHeaderHelper.create(asBase64(objectNode.toString()));

                assertThat(header.parameters.jwk.toString()).contains("RSA");
            }

            @Test
            void shouldAllowX509Headers() {
                objectNode.put("alg", "RS256");
                objectNode.put("alg", "RS256");
                objectNode.put("x5u", "x509_url");
                objectNode.putArray("x5c").add("x509_cert");
                objectNode.put("x5t", "x509_thumbprint_sha1");
                objectNode.put("x5t#S256", "x509_sha256");

                JwtHeader header = JwtHeaderHelper.create(asBase64(objectNode.toString()));

                assertThat(header.parameters.x5u).isEqualTo("x509_url");
                assertThat(header.parameters.x5c).isEqualTo(List.of("x509_cert"));
                assertThat(header.parameters.x5t).isEqualTo("x509_thumbprint_sha1");
                assertThat(header.parameters.x5tS256).isEqualTo("x509_sha256");
            }

            @Test
            void shouldAllowCritHeader() {
                objectNode.put("alg", "RS256");
                objectNode.putArray("crit")
                        .add("first-val")
                        .add("value-2");

                JwtHeader header = JwtHeaderHelper.create(asBase64(objectNode.toString()));

                assertThat(header.parameters.crit).contains("first-val", "value-2");
            }

            @Test
            void invalidHeader() {
                assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> JwtHeaderHelper.create(""));
            }
        }
    }

    private void validateJwtHeaders(JwtHeader header) {
        assertThat(header.parameters.typ).isEqualTo("JWT");
        assertThat(header.parameters.kid).isEqualTo("key-id");
        assertThat(header.parameters.alg).isEqualTo("key-alg");
        assertThat(header.parameters.enc).isEqualTo("key-encoding");
        assertThat(header.parameters.iv).isEqualTo("key-init-vector");
    }

    private String asBase64(String jwt) {
        return new String(Base64.getEncoder().encode(jwt.getBytes()));
    }
}
