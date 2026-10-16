package org.cloudfoundry.identity.uaa.oauth.tls;

import org.cloudfoundry.identity.uaa.client.InvalidClientDetailsException;
import org.cloudfoundry.identity.uaa.util.PemCertificateParser;

import java.util.LinkedHashMap;
import java.util.Map;

/** Resolves trust only from the supplied zone configuration; never falls back to another zone. */
public final class MtlsTrustBundles {
    private MtlsTrustBundles() { }

    public static void validate(Map<String, String> bundles) {
        if (bundles == null) {
            return;
        }
        bundles.forEach((name, pem) -> {
            if (name == null || !name.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,127}")) {
                throw new InvalidClientDetailsException("Invalid mTLS trust bundle name: " + name);
            }
            try {
                PemCertificateParser.parseCertificateChain(pem);
            } catch (IllegalArgumentException e) {
                throw new InvalidClientDetailsException("Invalid mTLS trust bundle '" + name + "': " + e.getMessage(), e);
            }
        });
    }

    public static String resolve(Map<String, Object> info, String inlineKey, String referenceKey,
            Map<String, String> bundles) {
        if (info.containsKey(inlineKey) && info.containsKey(referenceKey)) {
            throw new InvalidClientDetailsException(inlineKey + " and " + referenceKey + " are mutually exclusive");
        }
        if (info.containsKey(referenceKey)) {
            if (!(info.get(referenceKey) instanceof String name) || name.isBlank()) {
                throw new InvalidClientDetailsException(referenceKey + " must name a nonblank mTLS trust bundle");
            }
            String pem = bundles == null ? null : bundles.get(name);
            if (pem == null || pem.isBlank()) {
                throw new InvalidClientDetailsException(referenceKey + ": unknown or empty mTLS trust bundle '" + name + "'");
            }
            return pem;
        }
        if (info.containsKey(inlineKey)) {
            if (!(info.get(inlineKey) instanceof String pem) || pem.isBlank()) {
                throw new InvalidClientDetailsException(inlineKey + " must be a nonblank PEM string");
            }
            return pem;
        }
        return null;
    }

    public static String resolve(String inline, String reference, String inlineKey, String referenceKey,
            Map<String, String> bundles) {
        Map<String, Object> info = new LinkedHashMap<>();
        if (inline != null) {
            info.put(inlineKey, inline);
        }
        if (reference != null) {
            info.put(referenceKey, reference);
        }
        return resolve(info, inlineKey, referenceKey, bundles);
    }
}
