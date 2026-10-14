package org.cloudfoundry.identity.uaa.oauth.tls;

import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.context.annotation.Conditional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@Conditional(MtlsEnabledCondition.class)
public class MtlsTrustBundleEndpoints {
    public static final String PATH = "/oauth/mtls/trust-bundles";
    private final IdentityZoneManager identityZoneManager;

    public MtlsTrustBundleEndpoints(IdentityZoneManager identityZoneManager) {
        this.identityZoneManager = identityZoneManager;
    }

    @GetMapping(PATH)
    public Map<String, List<String>> names() {
        return Map.of("trust_bundles", identityZoneManager.getCurrentIdentityZone().getConfig()
                .getMtlsTrustBundles().keySet().stream().sorted().toList());
    }
}
