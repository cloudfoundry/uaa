/*
 * Copyright 2006-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.cloudfoundry.identity.uaa.oauth.jwt;

import com.nimbusds.jose.JWSAlgorithm;

import java.util.HashMap;
import java.util.Map;

/**
 * @author Luke Taylor
 */
public class JwtAlgorithms {
    public static final String DEFAULT_HMAC = "HMACSHA256";
    public static final String DEFAULT_EC = "SHA256withECDSA";
    public static final String DEFAULT_RSA = "SHA256withRSA";
    private static final Map<String, String> sigAlgs = new HashMap<>();
    private static final Map<String, String> javaToSigAlgs = new HashMap<>();
    private static final Map<String, String> keyAlgs = new HashMap<>();
    private static final Map<String, String> javaToKeyAlgs = new HashMap<>();

    static {
        sigAlgs.put("HS256", DEFAULT_HMAC);
        sigAlgs.put("HS384", "HMACSHA384");
        sigAlgs.put("HS512", "HMACSHA512");
        sigAlgs.put("RS256", DEFAULT_RSA);
        sigAlgs.put("RS384", "SHA384withRSA");
        sigAlgs.put("RS512", "SHA512withRSA");
        sigAlgs.put("PS256", "SHA256withRSAandMGF1");
        sigAlgs.put("PS384", "SHA384withRSAandMGF1");
        sigAlgs.put("PS512", "SHA512withRSAandMGF1");
        sigAlgs.put("ES256", DEFAULT_EC);
        sigAlgs.put("ES256K", DEFAULT_EC);
        sigAlgs.put("ES384", "SHA384withECDSA");
        sigAlgs.put("ES512", "SHA512withECDSA");

        keyAlgs.put("RSA1_5", "RSA/ECB/PKCS1Padding");

        for (Map.Entry<String, String> e : sigAlgs.entrySet()) {
            javaToSigAlgs.put(e.getValue(), e.getKey());
        }
        for (Map.Entry<String, String> e : keyAlgs.entrySet()) {
            javaToKeyAlgs.put(e.getValue(), e.getKey());
        }

    }

    public static String sigAlgJava(String sigAlg) {
        String alg = sigAlgs.get(sigAlg);

        if (alg == null) {
            throw new IllegalArgumentException("Invalid or unsupported signature algorithm: " + sigAlg);
        }

        return alg;
    }

    public static String sigAlg(String javaName) {
        String alg = JWSAlgorithm.parse(javaName).getName();

        if (alg == null) {
            throw new IllegalArgumentException("Invalid or unsupported signature algorithm: " + javaName);
        }

        return alg;
    }

    static String keyEncryptionAlg(String javaName) {
        String alg = javaToKeyAlgs.get(javaName);

        if (alg == null) {
            throw new IllegalArgumentException("Invalid or unsupported key encryption algorithm: " + javaName);
        }

        return alg;
    }
}
