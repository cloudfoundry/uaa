package org.cloudfoundry.identity.uaa.oauth.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.directory.api.util.Base64;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;

@DisplayName("JOSE Header https://tools.ietf.org/html/rfc7519#section-5")
public class JwtHeaderHelperTest {

    @DisplayName("JWS https://tools.ietf.org/html/rfc7519#ref-JWS")
    @Nested
    class JWS {

        @ParameterizedTest
        @ValueSource(strings = {"JWT", "jwt"})
        public void containsValidOptionalHeaders(String validTyp) {
            ObjectNode objectNode = new ObjectMapper().createObjectNode();
            objectNode.put("typ", validTyp);

            JwtHeader header = JwtHeaderHelper.create(asBase64(objectNode.toString()));

            assertThat(header.parameters.typ, is(validTyp));
        }

        @ParameterizedTest
        @ValueSource(strings = {"JWT", "jwt"})
        public void containsValidRequiredHeaders(String validCty) {
            ObjectNode objectNode = new ObjectMapper().createObjectNode();
            objectNode.put("cty", validCty);

            JwtHeader header = JwtHeaderHelper.create(asBase64(objectNode.toString()));

            assertThat(header.parameters.cty, is(validCty));
        }


    }


    @DisplayName("JWE https://tools.ietf.org/html/rfc7519#ref-JWE")
    @Nested
    class JWE {
        @DisplayName("Replicating Claims as Header Parameters https://tools.ietf.org/html/rfc7519#section-10.4.1")
        @Test
        public void containsValidReplicatedHeaders() {
            ObjectNode objectNode = new ObjectMapper().createObjectNode();
            objectNode.put("iss", "uaa.com");

            JwtHeader header = JwtHeaderHelper.create(asBase64(objectNode.toString()));

            assertThat(header.parameters.iss, is("uaa.com"));
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