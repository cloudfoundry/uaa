package org.cloudfoundry.identity.uaa.oauth.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.directory.api.util.Base64;
import org.cloudfoundry.identity.uaa.test.RandomParametersJunitExtension;
import org.cloudfoundry.identity.uaa.test.RandomParametersJunitExtension.RandomValue;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;

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

            Exception exception = Assertions.assertThrows(Exception.class,
                    () -> JwtHeaderHelper.create(asBase64(objectNode.toString()))
            );

            assertThat(exception.getMessage(), is(containsString("typ is not \"JWT\"")));
        }

        @DisplayName("given a valid signer it should serialize without error")
        @Test
        void shouldSerializeWithValidSigner() {
            final CommonSigner hmac = new CommonSigner("fake-key", "HMAC", null);

            JwtHeader header = JwtHeaderHelper.create(hmac.algorithm(), hmac.keyId(), hmac.keyURL());

            assertThat(header.parameters.typ, is("JWT"));
            assertThat(header.parameters.kid, is("fake-key"));
            assertThat(header.parameters.alg, is("HS256"));
            assertThat(header.parameters.enc, is(nullValue()));
            assertThat(header.parameters.iv, is(nullValue()));
        }

        @ParameterizedTest
        @ValueSource(strings = {"JWT", "jwt"})
        void canDeserializeCtyHeader(String validCty) {
            objectNode.put("cty", validCty);

            JwtHeader header = JwtHeaderHelper.create(asBase64(objectNode.toString()));

            assertThat(header.parameters.cty, is(validCty));
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

            assertThat(header.toString(), not(containsString("enc")));
            assertThat(header.toString(), not(containsString("iv")));
            assertThat(header.toString(), not(containsString("jwk")));
            assertThat(header.toString(), not(containsString("x5u")));
            assertThat(header.toString(), not(containsString("x5c")));
            assertThat(header.toString(), not(containsString("x5t")));
            assertThat(header.toString(), not(containsString("x5t#S256")));
            assertThat(header.toString(), not(containsString("crit")));
            // support not including `cty` if not present for back-compat
            assertThat(header.toString(), not(containsString("cty")));
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
                objectNode.put("typ", validTyp);

                JwtHeader header = JwtHeaderHelper.create(asBase64(objectNode.toString()));

                assertThat(header.parameters.typ, is(validTyp));
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
                objectNode.put("jwk", "key");

                JwtHeader header = JwtHeaderHelper.create(asBase64(objectNode.toString()));

                assertThat(header.parameters.jwk, is("key"));
            }

            @Test
            void shouldAllowX509Headers() {
                objectNode.put("x5u", "x509_url");
                objectNode.put("x5c", "x509_cert");
                objectNode.put("x5t", "x509_thumbprint_sha1");
                objectNode.put("x5t#S256", "x509_sha256");

                JwtHeader header = JwtHeaderHelper.create(asBase64(objectNode.toString()));

                assertThat(header.parameters.x5u, is("x509_url"));
                assertThat(header.parameters.x5c, is("x509_cert"));
                assertThat(header.parameters.x5t, is("x509_thumbprint_sha1"));
                assertThat(header.parameters.x5tS256, is("x509_sha256"));
            }

            @Test
            void shouldAllowCritHeader() {
                objectNode.putArray("crit")
                        .add("first-val")
                        .add("value-2");

                JwtHeader header = JwtHeaderHelper.create(asBase64(objectNode.toString()));

                assertThat(header.parameters.crit, hasItems("first-val", "value-2"));
            }
        }
    }

    private void validateJwtHeaders(JwtHeader header) {
        assertThat(header.parameters.typ, is("JWT"));
        assertThat(header.parameters.kid, is("key-id"));
        assertThat(header.parameters.alg, is("key-alg"));
        assertThat(header.parameters.enc, is("key-encoding"));
        assertThat(header.parameters.iv, is("key-init-vector"));
    }

    private String asBase64(String jwt) {
        return new String(Base64.encode(jwt.getBytes()));
    }
}