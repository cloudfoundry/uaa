package org.cloudfoundry.identity.uaa.account;

import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.test.ModelTestUtils.getResourceAsString;

class UserInfoResponseJsonTests {

    @Test
    void deserializeTest() {
        String json = getResourceAsString(this.getClass(), "UserInfoResponseJsonTests.json");

        assertHardcodedValues(json);
    }

    @Test
    void serializeTest() {
        String json = getResourceAsString(this.getClass(), "UserInfoResponseJsonTests.json");

        UserInfoResponse response = JsonUtils.readValue(json, UserInfoResponse.class);
        json = JsonUtils.writeValueAsString(response);
        assertHardcodedValues(json);
    }

    private static void assertHardcodedValues(String json) {
        UserInfoResponse response = JsonUtils.readValue(json, UserInfoResponse.class);
        assertThat(response.getEmail()).isEqualTo("olds@vmware.com");
        assertThat(response.getGivenName()).isEqualTo("Dale");
        assertThat(response.getFamilyName()).isEqualTo("Olds");
        assertThat(response.getFullName()).isEqualTo("Dale Olds");
        assertThat(response.getPhoneNumber()).isEqualTo("8505551234");
        assertThat(response.getUserId()).isEqualTo("12345");
        assertThat(response.getSub()).isEqualTo("12345");
        assertThat(response.getUserName()).isEqualTo("olds");
        assertThat(response.isEmailVerified()).isTrue();

        assertThat(response.getUserAttributes().get("Key 1")).contains("Val 11", "Val 12");
        assertThat(response.getUserAttributes().get("Key 2")).contains("Val 21", "Val 22");

        assertThat(response.getRoles()).contains("role12", "role54", "role134", "role812");
        assertThat(response.previousLogonSuccess).isEqualTo(Long.valueOf(1000L));
    }
}
