package org.cloudfoundry.identity.uaa.account;

import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AccountCreationResponseTest {

    @Test
    void serializedResponseDoesNotContainThePasswordResetCode() {
        AccountCreationService.AccountCreationResponse response = new AccountCreationService.AccountCreationResponse("user-id", "username", "user@example.com", "home");
        response.setPasswordResetCode("the_reset_code");

        String json = JsonUtils.writeValueAsString(response);

        assertThat(json)
                .contains("user_id", "user-id")
                .doesNotContain("password_reset_code", "the_reset_code");
    }
}
