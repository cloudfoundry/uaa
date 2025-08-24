package org.cloudfoundry.identity.uaa.oauth.jwt;

import com.nimbusds.jose.HeaderParameterNames;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKParameterNames;
import com.nimbusds.jose.jwk.JWKSet;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKeyHelper;

import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class SignatureVerifier implements Verifier {
    private final JsonWebKey delegate;
    private final String algorithm;
    private JWKSet jwk;

    public SignatureVerifier(String keyId, String alg, JWK verificationKey) {
        if (keyId == null || alg == null) {
            this.jwk = new JWKSet(verificationKey);
            this.delegate = JsonWebKeyHelper.parseConfiguration(verificationKey.toJSONString()).getKeys().getFirst();
            this.algorithm = this.delegate.getAlgorithm();
        } else {
            this.algorithm = alg;
            delegate = createJwkDelegate(keyId, alg, verificationKey);
        }
    }

    public SignatureVerifier(JsonWebKey verificationKey) {
        if (verificationKey == null) {
            throw new IllegalArgumentException("verificationKey cannot be null");
        }
        try {
            JWK webKey;
            if (verificationKey.getKty() == JsonWebKey.KeyType.RSA) {
                algorithm = Optional.ofNullable(verificationKey.getAlgorithm()).orElse(JWSAlgorithm.RS256.getName());
                webKey = verificationKey.hasValue() ?
                        JsonWebKeyHelper.getJsonWebKey(verificationKey.getValue()) :
                        JWK.parse(verificationKey.getKeyProperties());
            } else if (verificationKey.getKty() == JsonWebKey.KeyType.EC) {
                algorithm = Optional.ofNullable(verificationKey.getAlgorithm()).orElse(JWSAlgorithm.ES256.getName());
                webKey = JWK.parse(verificationKey.getKeyProperties());
            } else {
                Map<String, Object> webKeyHmac = new HashMap<>(verificationKey.getKeyProperties());
                webKeyHmac.put(JWKParameterNames.KEY_TYPE, JsonWebKey.KeyType.oct.name());
                if (webKeyHmac.containsKey(JsonWebKey.PUBLIC_KEY_VALUE)) {
                    webKeyHmac.put(JWKParameterNames.OCT_KEY_VALUE, verificationKey.getValue());
                }
                algorithm = Optional.ofNullable(verificationKey.getAlgorithm()).orElse(JWSAlgorithm.HS256.getName());
                webKey = JWK.parse(webKeyHmac);
            }
            String keyId = verificationKey.getKid();
            if (keyId == null || algorithm == null) {
                delegate = JsonWebKeyHelper.parseConfiguration(webKey.toJSONString()).getKeys().getFirst();
                jwk = new JWKSet(webKey);
            } else {
                delegate = createJwkDelegate(verificationKey.getKid(), algorithm, webKey);
            }
        } catch (ParseException | JOSEException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private JsonWebKey createJwkDelegate(String keyId, String alg, JWK verificationKey) {
        Map<String, Object> keyMap = verificationKey.toJSONObject();
        keyMap.put(HeaderParameterNames.KEY_ID, keyId);
        keyMap.put(HeaderParameterNames.ALGORITHM, alg);
        try {
            this.jwk = new JWKSet(JWK.parse(keyMap));
            return JsonWebKeyHelper.parseConfiguration(jwk.getKeyByKeyId(keyId).toJSONString()).getKeys().getFirst();
        } catch (ParseException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public String algorithm() {
        return algorithm;
    }

    public JWKSet getJwkSet() {
        return this.jwk;
    }

    public JWKSet getJwkSet(String keyId) {
        try {
            Map<String, Object> keyMap = new HashMap<>(delegate.getKeyProperties());
            keyMap.put(HeaderParameterNames.KEY_ID, keyId);
            return new JWKSet(JWK.parse(keyMap));
        } catch (ParseException e) {
            // ignore
        }
        return new JWKSet();
    }
}
