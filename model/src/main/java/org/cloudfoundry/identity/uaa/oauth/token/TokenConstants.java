/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.oauth.token;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class TokenConstants {
    public enum TokenFormat {
        OPAQUE("opaque"),
        JWT("jwt");

        private String stringValue;

        TokenFormat(String string) {
            this.stringValue = string;
        }

        public String getStringValue() {
            return this.stringValue;
        }

        static public TokenFormat fromStringValue(String stringValue) {
            for (TokenFormat tokenFormat : TokenFormat.values()) {
                if (tokenFormat.stringValue.equalsIgnoreCase(stringValue)) {
                    return tokenFormat;
                }
            }
            return null;
        }

        static public List<String> getStringValues() {
            return Arrays.stream(TokenFormat.values()).map(TokenFormat::getStringValue).collect(Collectors.toList());
        }
    }

    public static final String REQUEST_TOKEN_FORMAT = "token_format";
    public static final String REQUEST_AUTHORITIES = "authorities";

    public static final String USER_TOKEN_REQUESTING_CLIENT_ID = "requesting_client_id";
    public static final String REFRESH_TOKEN_SUFFIX = "-r";
    public static final String GRANT_TYPE_SAML2_BEARER = "urn:ietf:params:oauth:grant-type:saml2-bearer";
    public static final String GRANT_TYPE_JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    public static final String GRANT_TYPE_USER_TOKEN = "user_token";
    public static final String GRANT_TYPE_REFRESH_TOKEN = "refresh_token";
    public static final String GRANT_TYPE_PASSWORD = "password";
    public static final String GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials";
    public static final String GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code";
    public static final String GRANT_TYPE_IMPLICIT = "implicit";

    public static final String ID_TOKEN_HINT_PROMPT = "prompt";
    public static final String ID_TOKEN_HINT_PROMPT_NONE = "none";

}
