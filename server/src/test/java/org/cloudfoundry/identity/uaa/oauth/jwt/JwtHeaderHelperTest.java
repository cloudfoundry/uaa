package org.cloudfoundry.identity.uaa.oauth.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.directory.api.util.Base64;
import org.cloudfoundry.identity.uaa.test.RandomParametersJunitExtension;
import org.cloudfoundry.identity.uaa.test.RandomParametersJunitExtension.RandomValue;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.stream.Stream;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;

@Tag("https://tools.ietf.org/html/rfc7519#section-5")
@DisplayName("JOSE Header")
@ExtendWith(RandomParametersJunitExtension.class)
public class JwtHeaderHelperTest {

    @Tag("https://tools.ietf.org/html/rfc7519#ref-JWS")
    @DisplayName("JWS")
    @Nested
    class JWS {

        @ParameterizedTest
        @ValueSource(strings = {"JWT", "jwt"})
        public void containsValidOptionalTypHeaders(String validTyp) {
            ObjectNode objectNode = new ObjectMapper().createObjectNode();
            objectNode.put("typ", validTyp);

            JwtHeader header = JwtHeaderHelper.create(asBase64(objectNode.toString()));

            assertThat(header.parameters.typ, is(validTyp));
        }

        @DisplayName("should deserialize when provided optional enc/iv claims")
        @Test
        public void shouldAllowOptionalEncAndIvHeaders(@RandomValue String validEnc, @RandomValue String validIv) {
            ObjectNode objectNode = new ObjectMapper().createObjectNode();
            objectNode.put("enc", validEnc);
            objectNode.put("iv", validIv);

            JwtHeaderHelper.create(asBase64(objectNode.toString()));
        }

        @ParameterizedTest
        @ValueSource(strings = {"JWT", "jwt"})
        public void containsValidRequiredHeaders(String validCty) {
            ObjectNode objectNode = new ObjectMapper().createObjectNode();
            objectNode.put("cty", validCty);

            JwtHeader header = JwtHeaderHelper.create(asBase64(objectNode.toString()));

            assertThat(header.parameters.cty, is(validCty));
        }

        @Tag("https://tools.ietf.org/html/rfc7519#section-5.3")
        @Test
        public void shouldNotAllowAnyReplicatedHeaders(@RandomValue String randomVal) {
            ObjectNode objectNode = new ObjectMapper().createObjectNode();
            objectNode.put(randomVal, randomVal);

            Assertions.assertThrows(Exception.class, () ->
                    JwtHeaderHelper.create(asBase64(objectNode.toString()))
            );
        }

    }

    @Test
    public void createFromStringCorrectlyDecodesValidJSON() {
        String jwtJson = "{ " +
          "\"kid\": \"key-id\"," +
          "\"alg\": \"key-algorithm\"," +
          "\"enc\": \"key-encoding\"," +
          "\"iv\":  \"key-initialization-vector\"," +
          "\"typ\": \"JWT\"" +
          " }";

        JwtHeader header = JwtHeaderHelper.create(asBase64(jwtJson));

        assertThat(header.parameters.typ, is("JWT"));
        assertThat(header.parameters.kid, is("key-id"));
        assertThat(header.parameters.alg, is("key-algorithm"));
        assertThat(header.parameters.enc, is("key-encoding"));
        assertThat(header.parameters.iv, is("key-initialization-vector"));
    }

    @Test
    public void createFromStringThrowsExceptionWhenTypeIsNotJWT() {
        String jwtJson = "{ " +
          "\"kid\": \"key-id\"," +
          "\"alg\": \"key-algorithm\"," +
          "\"enc\": \"key-encoding\"," +
          "\"iv\":  \"key-initialization-vector\"," +
          "\"typ\": \"WTF\"" +
          " }";

        Exception exception = Assertions.assertThrows(Exception.class,
                () -> JwtHeaderHelper.create(asBase64(jwtJson))
        );

        assertThat(exception.getMessage(), is(containsString("typ is not \"JWT\"")));
    }

    @Test
    public void createFromStringThrowsExceptionWhenTypeIsEmpty() {
        String jwtJson = "{ " +
          "\"kid\": \"key-id\"," +
          "\"alg\": \"key-algorithm\"," +
          "\"enc\": \"key-encoding\"," +
          "\"iv\":  \"key-initialization-vector\"," +
          "\"typ\": \"\"" +
          " }";

        Assertions.assertThrows(Exception.class,
                () -> JwtHeaderHelper.create(asBase64(jwtJson))
        );
    }

    @Test
    public void createFromSigner() {
        final CommonSigner hmac = new CommonSigner("fake-key", "HMAC", null);
        JwtHeader header = JwtHeaderHelper.create(hmac.algorithm(), hmac.keyId(), hmac.keyURL());

        assertThat(header.parameters.typ, is("JWT"));
        assertThat(header.parameters.kid, is("fake-key"));
        assertThat(header.parameters.alg, is("HS256"));
        assertThat(header.parameters.enc, is(nullValue()));
        assertThat(header.parameters.iv, is(nullValue()));
    }

    @Test
    public void createFromSignerWithEmptyKeyId() {
        final CommonSigner hmac = new CommonSigner(null, "HMAC", null);
        JwtHeader header = JwtHeaderHelper.create(hmac.algorithm(), hmac.keyId(), hmac.keyURL());

        assertThat(header.parameters.typ, is("JWT"));
        assertThat(header.parameters.kid, is(nullValue()));
        assertThat(header.parameters.alg, is("HS256"));
        assertThat(header.parameters.enc, is(nullValue()));
        assertThat(header.parameters.iv, is(nullValue()));
    }

    private String asBase64(String jwt) {
        return new String(Base64.encode(jwt.getBytes()));
    }
}