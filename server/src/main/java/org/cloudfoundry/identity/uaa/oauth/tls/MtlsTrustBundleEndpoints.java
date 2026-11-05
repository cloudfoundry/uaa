package org.cloudfoundry.identity.uaa.oauth.tls;

import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
public class MtlsTrustBundleEndpoints {
    public static final String PATH = "/oauth/mtls/trust-bundles";
    private final IdentityZoneManager identityZoneManager;
    private final MtlsFeaturePolicy policy;

    public MtlsTrustBundleEndpoints(IdentityZoneManager identityZoneManager, MtlsFeaturePolicy policy) {
        this.identityZoneManager = identityZoneManager;
        this.policy = policy;
    }

    @GetMapping(PATH)
    public Map<String, List<String>> names() {
        if (!policy.isEnabled()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        return Map.of("trust_bundles", identityZoneManager.getCurrentIdentityZone().getConfig()
                .getMtls().getTrustBundles().keySet().stream().sorted().toList());
    }
}
