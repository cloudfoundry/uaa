package org.cloudfoundry.identity.uaa.spiffe;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SpiffeIdTests {

    @Test
    void formatsWorkloadSpiffeId() {
        CfInstanceIdentity identity = new CfInstanceIdentity("org-1", "space-2", "app-3");

        String id = SpiffeId.format("example.org", identity, "web");

        assertThat(id).isEqualTo(
                "spiffe://example.org/cf/org/org-1/space/space-2/app/app-3/process/web");
    }

    @Test
    void formatsSshProcessType() {
        CfInstanceIdentity identity = new CfInstanceIdentity("o", "s", "a");

        assertThat(SpiffeId.format("td", identity, "ssh"))
                .isEqualTo("spiffe://td/cf/org/o/space/s/app/a/process/ssh");
    }
}
