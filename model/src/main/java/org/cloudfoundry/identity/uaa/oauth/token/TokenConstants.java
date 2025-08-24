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

import org.cloudfoundry.identity.uaa.constants.ClientAuthentication;

import java.util.Arrays;
import java.util.List;

public class TokenConstants {
    public enum TokenFormat {
        OPAQUE("opaque"),
        JWT("jwt");

        private final String stringValue;

        TokenFormat(String string) {
            this.stringValue = string;
        }

        public String getStringValue() {
            return this.stringValue;
        }

        public static TokenFormat fromStringValue(String stringValue) {
            for (TokenFormat tokenFormat : TokenFormat.values()) {
                if (tokenFormat.stringValue.equalsIgnoreCase(stringValue)) {
                    return tokenFormat;
                }
            }
            return null;
        }

        public static List<String> getStringValues() {
            return Arrays.stream(TokenFormat.values()).map(TokenFormat::getStringValue).toList();
        }
    }

    public static final String ISSUED_TOKEN_TYPE = "issued_token_type";

    public static final String REQUEST_TOKEN_FORMAT = "token_format";
    public static final String REQUEST_TOKEN_TYPE = "request_token_type";
    public static final String REQUEST_TOKEN_FORMAT_JWT= "urn:ietf:params:oauth:token-type:jwt";
    public static final String REQUEST_AUTHORITIES = "authorities";

    public static final String TOKEN_TYPE_ACCESS = "urn:ietf:params:oauth:token-type:access_token";
    public static final String TOKEN_TYPE_REFRESH = "urn:ietf:params:oauth:token-type:refresh_token";
    public static final String TOKEN_TYPE_ID = "urn:ietf:params:oauth:token-type:id_token";
    public static final String TOKEN_TYPE_JWT = REQUEST_TOKEN_FORMAT_JWT;
    public static final String TOKEN_TYPE_SAML1_ASSERTION = "urn:ietf:params:oauth:token-type:saml1";
    public static final String TOKEN_TYPE_SAML2_ASSERTION = "urn:ietf:params:oauth:token-type:saml2";


    public static final String USER_TOKEN_REQUESTING_CLIENT_ID = "requesting_client_id";
    public static final String REFRESH_TOKEN_SUFFIX = "-r";
    public static final String GRANT_TYPE_SAML2_BEARER = "urn:ietf:params:oauth:grant-type:saml2-bearer";
    public static final String GRANT_TYPE_JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    public static final String GRANT_TYPE_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
    public static final String GRANT_TYPE_USER_TOKEN = "user_token";
    public static final String GRANT_TYPE_REFRESH_TOKEN = "refresh_token";
    public static final String GRANT_TYPE_PASSWORD = "password";
    public static final String GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials";
    public static final String GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code";
    public static final String GRANT_TYPE_IMPLICIT = "implicit";

    public static final String CLIENT_AUTH_NONE = ClientAuthentication.NONE;
    public static final String CLIENT_AUTH_EMPTY = "empty";
    public static final String CLIENT_AUTH_SECRET = "secret";
    public static final String CLIENT_AUTH_PRIVATE_KEY_JWT = ClientAuthentication.PRIVATE_KEY_JWT;

    public static final String ID_TOKEN_HINT_PROMPT = "prompt";
    public static final String ID_TOKEN_HINT_PROMPT_NONE = "none";

    public static final String SUBJECT_TOKEN = "subject_token";
    public static final String SUBJECT_TOKEN_TYPE = "subject_token_type";
    public static final String TOKEN_EXCHANGE_IMPERSONATE_CLIENT_PERMISSION = "token_exchange.impersonate.%s";

}
