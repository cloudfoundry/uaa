package org.cloudfoundry.identity.uaa.oauth.beans;

import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class OauthEndpointBeanConfigurationTest {

    @Test
    void testUaaTokenPolicyFailsWhenRotateJwtAndNotRevocable() {
        OauthEndpointBeanConfiguration config = new OauthEndpointBeanConfiguration();

        assertThatIllegalArgumentException().isThrownBy(() -> {
            config.uaaTokenPolicy(
                    3600,
                    7200,
                    Collections.emptyMap(),
                    "defaultKey",
                    false, // jwtRevocable = false
                    TokenConstants.TokenFormat.JWT.getStringValue(),
                    "false",
                    true // refreshTokenRotate = true
            );
        }).withMessage("A token policy cannot have JWT-format refresh tokens with rotation enabled unless they are also revocable.");
    }
}
