package org.cloudfoundry.identity.uaa.mock.token;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@DefaultTestContext
@TestPropertySource(locations = "classpath:mtls-trust-bundles.properties")
class MtlsTrustBundleConfigurationTests {
    @Autowired
    IdentityZoneProvisioning provisioning;

    @Test
    void operatorConfigurationPopulatesOnlyTheDefaultZonesTrustBundles() {
        Map<String, Object> config = JsonUtils.convertValue(
                provisioning.retrieve(IdentityZone.getUaaZoneId()).getConfig(), Map.class);
        assertThat(config).as("uaa.mtls.trust_bundles must populate the default zone at startup")
                .containsKey("mtls").doesNotContainKey("mtlsTrustBundles");
        Map<String, Object> mtls = (Map<String, Object>) config.get("mtls");
        assertThat(mtls).containsEntry("enabled", true);
        assertThat((Map<String, Object>) mtls.get("trustBundles")).containsKey("configured-ca");
        IdentityZone other = new IdentityZone();
        assertThat(JsonUtils.convertValue(other.getConfig(), Map.class))
                .containsEntry("mtls", Map.of("enabled", true, "trustBundles", Map.of()));
    }
}
