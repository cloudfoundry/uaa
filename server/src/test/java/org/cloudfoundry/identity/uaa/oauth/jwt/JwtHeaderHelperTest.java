package org.cloudfoundry.identity.uaa.oauth.jwt;

import org.apache.directory.api.util.Base64;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;

public class JwtHeaderHelperTest {
    @Rule
    public ExpectedException expectedException = ExpectedException.none();

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

        expectedException.expect(Exception.class);
        expectedException.expectMessage("typ is not \"JWT\"");

        JwtHeaderHelper.create(asBase64(jwtJson));
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

        expectedException.expect(Exception.class);
        expectedException.expectMessage("typ is not \"JWT\"");

        JwtHeaderHelper.create(asBase64(jwtJson));
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