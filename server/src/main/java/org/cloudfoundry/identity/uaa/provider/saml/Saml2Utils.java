/*
 * Copyright 2002-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.cloudfoundry.identity.uaa.provider.saml;

import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.Saml2ErrorCodes;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterOutputStream;

/**
 * This class contains functions to Encode, Decode, Deflate and Inflate SAML messages.
 * <p>
 * It was copied from Spring-Security
 * org.springframework.security.saml2.core.Saml2Utils
 * <p>
 * There are multiple copies of this class in the Spring-Security code, this particular one exposes functionality publicly.
 * Others are only used internally.
 */
public final class Saml2Utils {

    private Saml2Utils() {
        throw new java.lang.UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    public static String samlEncode(byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }

    public static String samlBearerEncode(byte[] b) {
        return Base64.getUrlEncoder().encodeToString(b);
    }

    public static byte[] samlDecode(String s) {
        return Base64.getMimeDecoder().decode(s);
    }

    public static byte[] samlBearerDecode(String s) {
        try {
            return Base64.getUrlDecoder().decode(s);
        } catch (IllegalArgumentException ex) {
            throw OpenSaml4AuthenticationProvider.createAuthenticationException(Saml2ErrorCodes.INVALID_ASSERTION, "Unable to urlBase64Decode bearer assertion", ex);
        }
    }

    public static byte[] samlDeflate(String s) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(out,
                    new Deflater(Deflater.DEFLATED, true));
            deflaterOutputStream.write(s.getBytes(StandardCharsets.UTF_8));
            deflaterOutputStream.finish();
            return out.toByteArray();
        } catch (IOException ex) {
            throw new Saml2Exception("Unable to deflate string", ex);
        }
    }

    public static String samlInflate(byte[] b) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            InflaterOutputStream inflaterOutputStream = new InflaterOutputStream(out, new Inflater(true));
            inflaterOutputStream.write(b);
            inflaterOutputStream.finish();
            return out.toString(StandardCharsets.UTF_8);
        } catch (IOException ex) {
            throw new Saml2Exception("Unable to inflate string", ex);
        }
    }

    /*****************************************************************************
     * Below are convenience methods not originally in the Spring-Security class
     *****************************************************************************/

    public static String samlBearerEncode(String s) {
        return samlBearerEncode(s.getBytes(StandardCharsets.UTF_8));
    }

    public static String samlDecodeAndInflate(String s) {
        return samlInflate(samlDecode(s));
    }
}
