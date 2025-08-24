package org.cloudfoundry.identity.uaa.error;

import org.cloudfoundry.identity.uaa.oauth.common.exceptions.OAuth2Exception;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class UaaExceptionTests {

    @Test
    void getErrorCode() {
        UaaException x = new UaaException("msg", new Exception());
        assertThat(x.getErrorCode()).isEqualTo("unknown_error");
        x = new UaaException("msg");
        assertThat(x.getErrorCode()).isEqualTo("unknown_error");
        x = new UaaException("msg", 500);
        assertThat(x.getErrorCode()).isEqualTo("unknown_error");
        x = new UaaException("Error", "description", 500);
        assertThat(x.getErrorCode()).isEqualTo("Error");
    }

    @Test
    void getHttpStatus() {
        UaaException x = new UaaException("msg", new Exception());
        assertThat(x.getHttpStatus()).isEqualTo(400);
        x = new UaaException("msg");
        assertThat(x.getHttpStatus()).isEqualTo(400);
        x = new UaaException("msg", 500);
        assertThat(x.getHttpStatus()).isEqualTo(500);
        x = new UaaException("Error", "description", 500);
        assertThat(x.getHttpStatus()).isEqualTo(500);

        assertThat(x.getSummary()).isNotNull();
    }

    @Test
    void valueOf() {
        Map<String, String> params = new HashMap<>();
        params.put("error", "error");
        params.put("error_description", "error_description");
        params.put("status", "403");
        params.put("additional1", "additional1");
        params.put("additional2", "additional2");
        UaaException x = UaaException.valueOf(params);
        assertThat(x.getErrorCode()).isEqualTo("error");
        assertThat(x.getMessage()).isEqualTo("error_description");
        assertThat(x.getHttpStatus()).isEqualTo(403);
        assertThat(x.getAdditionalInformation()).containsEntry("additional1", "additional1")
                .containsEntry("additional2", "additional2");

        params.put("status", "test");
        x = UaaException.valueOf(params);
        assertThat(x.getErrorCode()).isEqualTo("error");
        assertThat(x.getMessage()).isEqualTo("error_description");
        assertThat(x.getHttpStatus()).isEqualTo(400);
        assertThat(x.getAdditionalInformation()).containsEntry("additional1", "additional1")
                .containsEntry("additional2", "additional2")
                .doesNotContainKey("additional3");

        x.addAdditionalInformation("additional3", "additional3");
        assertThat(x.getAdditionalInformation()).containsEntry("additional1", "additional1")
                .containsEntry("additional2", "additional2")
                .containsEntry("additional3", "additional3");

        assertThat(x.getSummary()).isNotNull()
                .contains("error=\"error\"")
                .contains("additional3=\"additional3\"");
    }

    @Test
    void testToString() {
        UaaException x = new UaaException("test");
        assertThat(x.toString()).isNotNull();
    }

    @Test
    void serialize() {
        Map<String, String> params = Map.of("error", "invalid_request", "error_description", "error_description");
        UaaException x = UaaException.valueOf(params);
        String uaaExceptionString = JsonUtils.writeValueAsString(x);
        OAuth2Exception deserialized = JsonUtils.readValue(uaaExceptionString, UaaException.class);
        assertThat(JsonUtils.writeValueAsString(deserialized)).isEqualTo(uaaExceptionString);
        UaaException newException = new UaaException(deserialized, deserialized.getOAuth2ErrorCode(), "error_description", 400);
        assertThat(x).hasToString(newException.toString());
    }
}
