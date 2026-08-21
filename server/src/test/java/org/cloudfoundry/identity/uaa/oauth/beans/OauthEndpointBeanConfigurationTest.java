package org.cloudfoundry.identity.uaa.oauth.beans;

import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;

class OauthEndpointBeanConfigurationTest {

    @Test
    void testUaaTokenPolicyAutoCorrectsWhenRotateJwtAndNotRevocable() {
        OauthEndpointBeanConfiguration config = new OauthEndpointBeanConfiguration();

        TokenPolicy tokenPolicy = config.uaaTokenPolicy(
                3600,
                7200,
                Collections.emptyMap(),
                "defaultKey",
                false, // jwtRevocable = false
                TokenConstants.TokenFormat.JWT.getStringValue(),
                "false",
                true // refreshTokenRotate = true
        );
        
        assertThat(tokenPolicy.isJwtRevocable()).isTrue();
    }
}
