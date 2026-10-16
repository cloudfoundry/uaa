package org.cloudfoundry.identity.uaa.oauth.tls;

import java.util.Map;

/** Named trust bundles. Not implemented yet: nothing is validated and no trust is resolved. */
public final class MtlsTrustBundles {

    private MtlsTrustBundles() {
    }

    public static void validate(Map<String, String> bundles) {
    }

    public static String resolve(Map<String, Object> info, String inlineKey, String referenceKey,
            Map<String, String> bundles) {
        return null;
    }

    public static String resolve(String inline, String reference, String inlineKey, String referenceKey,
            Map<String, String> bundles) {
        return null;
    }
}
