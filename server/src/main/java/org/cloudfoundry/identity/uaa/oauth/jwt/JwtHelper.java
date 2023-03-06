package org.cloudfoundry.identity.uaa.oauth.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.text.ParseException;

/**
 * @author Luke Taylor
 * @author Dave Syer
 */
public class JwtHelper {
    static final byte[] PERIOD = new String(".").getBytes();

    /**
     * Creates a token from an encoded token string.
     *
     * @param token the (non-null) encoded token (three Base-64 encoded strings separated
     *              by "." characters)
     */
    public static Jwt decode(String token) {
        int firstPeriod = token.indexOf('.');
        int lastPeriod = token.lastIndexOf('.');

        if (firstPeriod <= 0 || lastPeriod <= firstPeriod) {
            throw new IllegalArgumentException("JWT must have 3 tokens");
        }
        JWT jwt;
        Base64URL[] parsedParts;
        JWSObject jwsObject;
        try {
            jwt = JWTParser.parse(token);
            parsedParts = jwt.getParsedParts();
            jwsObject = new JWSObject(parsedParts[0], parsedParts[1], parsedParts[2]);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
        CharBuffer buffer = CharBuffer.wrap(token, 0, firstPeriod);
        JwtHeader header = JwtHeaderHelper.create(jwt.getHeader().toString());

        buffer.limit(lastPeriod).position(firstPeriod + 1);
        boolean emptyCrypto = lastPeriod == token.length() - 1;
        byte[] crypto;

        if (emptyCrypto) {
            if (!"none".equals(header.parameters.alg)) {
                throw new IllegalArgumentException(
                  "Signed or encrypted token must have non-empty crypto segment");
            }
            crypto = new byte[0];
        } else {
            buffer.limit(token.length()).position(lastPeriod + 1);
            crypto = new Base64URL(buffer.toString()).decode();
        }
        return new JwtImpl(header, jwsObject, crypto);
    }

    public static Jwt encode(CharSequence content, KeyInfo keyInfo) {
        JwtHeader header = JwtHeaderHelper.create(keyInfo.algorithm(), keyInfo.keyId(), keyInfo.keyURL());
        JWSObject jwsObject = new JWSObject(header.header(), new Payload(content.toString()));
        try {
            jwsObject.sign(keyInfo.getSigner());
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
        return new JwtImpl(header, jwsObject, jwsObject.getSignature().decode());
    }
}

/**
 * Helper object for JwtHeader.
 * <p>
 * Handles the JSON parsing and serialization.
 */
class JwtHeaderHelper {
    static JwtHeader create(String header) {
        JWSHeader jwsHeader;
        try {
            jwsHeader = JWSHeader.parse(header);
        } catch (ParseException e) {
            jwsHeader = null;
        }

        return new JwtHeader(jwsHeader, JsonUtils.readValue(header, HeaderParameters.class));
    }

    static JwtHeader create(String algorithm, String kid, String jku) {
        HeaderParameters headerParameters = new HeaderParameters(algorithm, kid, jku);

        try {
            JWSHeader.Builder jwsHeaderBuilder = new JWSHeader.Builder(JWSAlgorithm.parse(algorithm)).keyID(kid);
            if (jku != null) {
                jwsHeaderBuilder.jwkURL(new URI(jku));
            }
            return new JwtHeader(jwsHeaderBuilder.build(), headerParameters);
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }
}

/**
 * Header part of JWT
 */
class JwtHeader {
    private final JWSHeader jwsHeader;

    final HeaderParameters parameters;

    /**
     * @param bytes      the decoded header
     * @param parameters the parameter values contained in the header
     */
    JwtHeader(JWSHeader jwsHeader, HeaderParameters parameters) {
        this.jwsHeader = jwsHeader;
        this.parameters = parameters;
    }

    public JWSHeader header() {
        return jwsHeader;
    }

    @Override
    public String toString() {
        return jwsHeader.toJSONObject().toString();
    }
}

class JwtImpl implements Jwt {
    private static Charset UTF8 = Charset.forName("UTF-8");
    private final JwtHeader header;
    private final JWSObject jwsObject;

    private final byte[] crypto;

    private String claims;

    /**
     * @param header  the header, containing the JWS/JWE algorithm information.
     * @param content the base64-decoded "claims" segment (may be encrypted, depending on
     *                header information).
     * @param crypto  the base64-decoded "crypto" segment.
     */
    JwtImpl(JwtHeader header, JWSObject jwsObject, byte[] crypto) {
        this.header = header;
        this.jwsObject = jwsObject;
        this.crypto = crypto;
        this.claims = jwsObject.getPayload().toString();
    }

    /**
     * Validates a signature contained in the 'crypto' segment.
     *
     * @param verifier the signature verifier
     */
    public void verifySignature(JWSVerifier verifier) {
        try {
            boolean verified = false;
            if (verifier instanceof ChainedSignatureVerifier) {
                ChainedSignatureVerifier chainedSignatureVerifier = (ChainedSignatureVerifier) verifier;
                verified = chainedSignatureVerifier.verify(jwsObject);
            } else {
                verified = jwsObject.verify(verifier);
            }
            if (!verified) {
                throw new InvalidTokenException("JWS verify failed");
            }
        } catch (JOSEException e) {
            throw new InvalidTokenException("JWS verify failed", e);
        }
    }

    private byte[] signingInput() {
        return null;//concat(safeB64UrlEncode(header.bytes()), JwtHelper.PERIOD,safeB64UrlEncode(content));
    }

    private byte[] safeB64UrlEncode(byte[] bytes) {
        if (bytes.length == 0) {
            return bytes;
        } else {
            return null;//b64UrlEncode(bytes);
        }
    }

    /**
     * Allows retrieval of the full token.
     *
     * @return the encoded header, claims and crypto segments concatenated with "."
     * characters
     */

    public byte[] bytes() {
        return null;//concat(b64UrlEncode(header.bytes()), JwtHelper.PERIOD,b64UrlEncode(content), JwtHelper.PERIOD, b64UrlEncode(crypto));
    }


    public String getClaims() {
        return jwsObject.getPayload().toString();
    }


    public String getEncoded() {
        return this.jwsObject.serialize();
    }


    public String toString() {
        return header + " " + claims + " [" + crypto.length + " crypto bytes]";
    }


    public HeaderParameters getHeader() {
        return header == null ? null : header.parameters;
    }
}
