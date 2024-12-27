package org.cloudfoundry.identity.uaa.oauth.common.exceptions;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 exceptions
 */
@SuppressWarnings("serial")
public class OAuth2ExceptionJackson2Deserializer extends StdDeserializer<OAuth2Exception> {

    public OAuth2ExceptionJackson2Deserializer(Class vc) {
        super(vc);
    }

    public OAuth2ExceptionJackson2Deserializer() {
        super(OAuth2Exception.class);
    }

    @Override
    public OAuth2Exception deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException {

        JsonToken t = jp.getCurrentToken();
        if (t == JsonToken.START_OBJECT) {
            t = jp.nextToken();
        }
        Map<String, Object> errorParams = new HashMap<>();
        for (; t == JsonToken.FIELD_NAME; t = jp.nextToken()) {
            // Must point to field name
            String fieldName = jp.getCurrentName();
            // And then the value...
            t = jp.nextToken();
            // Note: must handle null explicitly here; value deserializers won't
            Object value;
            if (t == JsonToken.VALUE_NULL) {
                value = null;
            } else if (t == JsonToken.START_ARRAY) {
                value = jp.readValueAs(List.class);
            } else if (t == JsonToken.START_OBJECT) {
                value = jp.readValueAs(Map.class);
            } else {
                value = jp.getText();
            }
            errorParams.put(fieldName, value);
        }

        Object errorCode = errorParams.get(OAuth2Exception.ERROR);
        String errorMessage = errorParams.get(OAuth2Exception.DESCRIPTION) != null ? errorParams.get(OAuth2Exception.DESCRIPTION).toString() : null;
        if (errorMessage == null) {
            errorMessage = errorCode == null ? "OAuth Error" : errorCode.toString();
        }

        OAuth2Exception ex;
        if ("invalid_client".equals(errorCode)) {
            ex = new InvalidClientException(errorMessage);
        } else if ("unauthorized_client".equals(errorCode)) {
            ex = new UnauthorizedClientException(errorMessage);
        } else if ("invalid_grant".equals(errorCode)) {
            if (errorMessage.toLowerCase().contains("redirect") && errorMessage.toLowerCase().contains("match")) {
                ex = new RedirectMismatchException(errorMessage);
            } else {
                ex = new InvalidGrantException(errorMessage);
            }
        } else if ("invalid_scope".equals(errorCode)) {
            ex = new InvalidScopeException(errorMessage);
        } else if ("invalid_token".equals(errorCode)) {
            ex = new InvalidTokenException(errorMessage);
        } else if ("invalid_request".equals(errorCode)) {
            ex = new InvalidRequestException(errorMessage);
        } else if ("redirect_uri_mismatch".equals(errorCode)) {
            ex = new RedirectMismatchException(errorMessage);
        } else if ("unsupported_grant_type".equals(errorCode)) {
            ex = new UnsupportedGrantTypeException(errorMessage);
        } else if ("unsupported_response_type".equals(errorCode)) {
            ex = new UnsupportedResponseTypeException(errorMessage);
        } else if ("insufficient_scope".equals(errorCode)) {
            ex = new InsufficientScopeException(errorMessage, OAuth2Utils.parseParameterList((String) errorParams
                    .get("scope")));
        } else if ("access_denied".equals(errorCode)) {
            ex = new UserDeniedAuthorizationException(errorMessage);
        } else {
            ex = new OAuth2Exception(errorMessage);
        }

        Set<Map.Entry<String, Object>> entries = errorParams.entrySet();
        for (Map.Entry<String, Object> entry : entries) {
            String key = entry.getKey();
            if (!OAuth2Exception.ERROR.equals(key) && !OAuth2Exception.DESCRIPTION.equals(key)) {
                Object value = entry.getValue();
                ex.addAdditionalInformation(key, value == null ? null : value.toString());
            }
        }

        return ex;

    }

}
