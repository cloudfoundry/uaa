/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */
package org.cloudfoundry.identity.uaa.oauth.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;
import org.springframework.security.jwt.crypto.sign.EllipticCurveVerifier;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;

import javax.crypto.spec.SecretKeySpec;
import java.text.ParseException;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CommonSignatureVerifier implements SignatureVerifier {

    private static final Pattern PEM_DATA = Pattern.compile("-----BEGIN (.*)-----(.*)-----END (.*)-----", Pattern.DOTALL);
    private static final Pattern WS_DATA = Pattern.compile("\\s", Pattern.UNICODE_CHARACTER_CLASS);
    private static final int PATTERN_TYPE = 1;
    private static final int PATTERN_CONTENT = 2;
    private final SignatureVerifier delegate;

    public CommonSignatureVerifier(JsonWebKey verificationKey) {
        if(verificationKey == null) {
            throw new IllegalArgumentException("verificationKey cannot be null");
        } else if(verificationKey.getKty() == JsonWebKey.KeyType.RSA) {
            try {
                RSAKey rsaKey = verificationKey.getValue() != null ? getRsaKey(verificationKey.getValue()) : RSAKey.parse(verificationKey.getKeyProperties());
                String jwtAlg = Optional.ofNullable(verificationKey.getAlgorithm()).orElse(JWSAlgorithm.RS256.getName());
                delegate = new RsaVerifier(rsaKey.toRSAPublicKey(), JwtAlgorithms.sigAlgJava(jwtAlg));
            } catch (ParseException | JOSEException e) {
                throw new IllegalArgumentException(e);
            }
        } else if(verificationKey.getKty() == JsonWebKey.KeyType.EC) {
            try {
                ECKey ecKey = ECKey.parse(verificationKey.getKeyProperties());
                String jwtAlg = Optional.ofNullable(verificationKey.getAlgorithm()).orElse(JWSAlgorithm.ES256.getName());
                delegate = new EllipticCurveVerifier(ecKey.toECPublicKey(), JwtAlgorithms.sigAlgJava(jwtAlg));
            } catch (ParseException | JOSEException e) {
                throw new IllegalArgumentException(e);
            }
        } else {
            String jwtAlg = Optional.ofNullable(verificationKey.getAlgorithm()).orElse(JWSAlgorithm.HS256.getName());
            delegate = new MacSigner(JwtAlgorithms.sigAlgJava(jwtAlg), new SecretKeySpec(verificationKey.getValue().getBytes(), jwtAlg));
        }
    }

    @Override
    public void verify(byte[] content, byte[] signature) {
        delegate.verify(content, signature);
    }

    @Override
    public String algorithm() {
        return delegate.algorithm();
    }

    private static RSAKey getRsaKey(String jsonData) throws JOSEException {
        Matcher m = PEM_DATA.matcher(jsonData.trim());
        if (!m.matches()) {
            throw new IllegalArgumentException("String is not PEM encoded data");
        }
        String begin = "-----BEGIN " + m.group(PATTERN_TYPE) + "-----\n";
        String end = "\n-----END " + m.group(PATTERN_TYPE) + "-----";
        return JWK.parseFromPEMEncodedObjects(begin + WS_DATA.matcher(m.group(PATTERN_CONTENT).trim()).replaceAll("\n") + end).toRSAKey();
    }
}
