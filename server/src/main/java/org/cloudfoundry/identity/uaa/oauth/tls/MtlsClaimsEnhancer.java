package org.cloudfoundry.identity.uaa.oauth.tls;

import org.cloudfoundry.identity.uaa.client.TlsClientAuthConfiguration;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.UaaTokenEnhancer;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import tools.jackson.core.type.TypeReference;

import javax.security.auth.x500.X500Principal;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A {@link UaaTokenEnhancer} that enriches access tokens with claims derived from the
 * mTLS client certificate presented during the {@code /oauth/mtls/token} flow.
 *
 * <p>When a client configured with {@code tls-client-auth} authenticates, this enhancer:
 * <ul>
 *   <li>Maps certificate subject fields (CN, OU, O) to JWT claims as configured per-client.</li>
 *   <li>Adds a {@code cnf.x5t#S256} confirmation claim (RFC 8705 §3.1).</li>
 * </ul>
 *
 * <p>Spring auto-wires this bean into
 * {@link org.cloudfoundry.identity.uaa.oauth.UaaTokenServices#setUaaTokenEnhancers} via
 * {@code @Autowired(required = false)}.
 */
@Component
public class MtlsClaimsEnhancer implements UaaTokenEnhancer {

    private static final Logger logger = LoggerFactory.getLogger(MtlsClaimsEnhancer.class);

    private final TlsClientAuthentication tlsClientAuthentication;
    private final ClientDetailsService clientDetailsService;

    @Autowired
    public MtlsClaimsEnhancer(TlsClientAuthentication tlsClientAuthentication,
                               ClientDetailsService clientDetailsService) {
        this.tlsClientAuthentication = tlsClientAuthentication;
        this.clientDetailsService = clientDetailsService;
    }

    /**
     * Not used — all enrichment is performed in {@link #enhance}.
     */
    @Override
    public Map<String, String> getExternalAttributes(OAuth2Authentication authentication) {
        return Map.of();
    }

    /**
     * Returns a map of additional top-level JWT claims derived from the client certificate.
     * Returns an empty map when no certificate is present on the request.
     */
    @Override
    public Map<String, Object> enhance(Map<String, Object> claims, OAuth2Authentication authentication) {
        X509Certificate cert = tlsClientAuthentication.getCertificateFromRequest();
        if (cert == null) {
            return new HashMap<>();
        }

        String clientId = authentication.getOAuth2Request().getClientId();
        UaaClientDetails clientDetails;
        try {
            clientDetails = (UaaClientDetails) clientDetailsService.loadClientByClientId(clientId);
        } catch (Exception e) {
            logger.warn("MtlsClaimsEnhancer: failed to load client details for '{}': {}", clientId, e.getMessage());
            return new HashMap<>();
        }

        TlsClientAuthConfiguration config = clientDetails.getTlsClientAuthConfiguration();
        if (config == null) {
            config = loadTlsConfig(clientDetails.getAdditionalInformation());
        }
        if (!TlsClientAuthConfiguration.isConfigured(config)) {
            return new HashMap<>();
        }

        // PHASE 1 — extract cert subject fields into vars (keyed by claim name)
        Map<String, String> vars = new HashMap<>();
        if (config.getClaimMappings() != null) {
            X500Principal subject = cert.getSubjectX500Principal();
            String dn = subject.getName(X500Principal.RFC2253);
            String cn  = extractRdnValue(dn, "CN=");
            List<String> ous = extractOus(dn);

            for (TlsClientAuthConfiguration.ClaimMapping mapping : config.getClaimMappings()) {
                String value = switch (mapping.getField()) {
                    case "subject_cn" -> cn;
                    case "subject_ou" -> matchFirstOu(ous, mapping.getPattern());
                    case "subject_o"  -> extractRdnValue(dn, "O=");
                    default -> null;
                };
                if (value != null && !value.isBlank()) {
                    vars.put(mapping.getClaim(), value);
                }
            }
        }

        // PHASE 2 — build JWT claims: dot-notation → nested object; flat → top-level
        Map<String, Object> result = new HashMap<>();
        Map<String, Map<String, Object>> nestedClaims = new HashMap<>();
        for (Map.Entry<String, String> entry : vars.entrySet()) {
            String key   = entry.getKey();
            String value = entry.getValue();
            int dotIdx = key.indexOf('.');
            if (dotIdx > 0 && dotIdx < key.length() - 1) {
                String parent = key.substring(0, dotIdx);
                String child  = key.substring(dotIdx + 1);
                nestedClaims.computeIfAbsent(parent, k -> new HashMap<>()).put(child, value);
            } else {
                result.put(key, value);
            }
        }
        // Nested maps overwrite any flat claim that shares the same parent key
        result.putAll(nestedClaims);

        // Always add cnf.x5t#S256 (RFC 8705 §3.1 confirmation claim)
        try {
            byte[] derEncoded = cert.getEncoded();
            byte[] sha256 = MessageDigest.getInstance("SHA-256").digest(derEncoded);
            String thumbprint = Base64.getUrlEncoder().withoutPadding().encodeToString(sha256);
            result.put("cnf", Map.of("x5t#S256", thumbprint));
        } catch (Exception ignored) {
            // Silently skip cnf claim if cert encoding fails
        }

        // PHASE 3 — template rendering (added in next task)

        return result;
    }

    /**
     * Extracts the value of a single-valued RDN (e.g. {@code "CN="}) from a RFC 2253 DN string.
     * Handles multi-valued RDNs (attributes joined by {@code +}).
     * Returns {@code null} if no matching RDN is found.
     */
    private String extractRdnValue(String dn, String prefix) {
        for (String rdn : dn.split(",")) {
            // Multi-valued RDNs use '+' to separate attribute-value pairs within one RDN
            for (String attrVal : rdn.split("\\+")) {
                String trimmed = attrVal.trim();
                if (trimmed.startsWith(prefix)) {
                    return trimmed.substring(prefix.length());
                }
            }
        }
        return null;
    }

    /**
     * Collects all OU values from a RFC 2253 DN string, in order.
     * Handles multi-valued RDNs (attributes joined by {@code +}).
     */
    private List<String> extractOus(String dn) {
        List<String> ous = new ArrayList<>();
        for (String rdn : dn.split(",")) {
            // Multi-valued RDNs use '+' to separate attribute-value pairs within one RDN
            for (String attrVal : rdn.split("\\+")) {
                String trimmed = attrVal.trim();
                if (trimmed.startsWith("OU=")) {
                    ous.add(trimmed.substring(3));
                }
            }
        }
        return ous;
    }

    /**
     * Returns the first captured group from the first OU that matches {@code patternStr}.
     * When {@code patternStr} is null or blank, returns the first OU value verbatim.
     */
    private String matchFirstOu(List<String> ous, String patternStr) {
        if (patternStr == null || patternStr.isBlank()) {
            return ous.isEmpty() ? null : ous.get(0);
        }
        Pattern pat = Pattern.compile(patternStr);
        for (String ou : ous) {
            Matcher m = pat.matcher(ou);
            if (m.matches() && m.groupCount() >= 1) {
                return m.group(1);
            }
        }
        return null;
    }

    /**
     * Builds a {@link TlsClientAuthConfiguration} from the client's {@code additionalInformation} map.
     * Mirrors {@code ClientDetailsAuthenticationProvider.getTlsClientAuthConfiguration} so that
     * DB-loaded clients (whose {@code tlsClientAuthConfiguration} field is null) are handled correctly.
     */
    private static TlsClientAuthConfiguration loadTlsConfig(Map<String, Object> info) {
        if (info == null) {
            return null;
        }
        Object raw = info.get(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA);
        if (raw instanceof TlsClientAuthConfiguration cfg) {
            return cfg;  // in-memory / test client
        }
        if (raw instanceof Map<?, ?>) {
            try {
                return JsonUtils.convertValue(raw, TlsClientAuthConfiguration.class);
            } catch (Exception e) {
                return null;
            }
        }
        if (raw instanceof String pem) {
            try {
                List<TlsClientAuthConfiguration.ClaimMapping> claimMappings = null;
                Object rawMappings = info.get(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS);
                if (rawMappings instanceof String mappingsJson) {
                    claimMappings = JsonUtils.readValue(mappingsJson,
                            new TypeReference<List<TlsClientAuthConfiguration.ClaimMapping>>() {});
                } else if (rawMappings instanceof List<?> mappingsList) {
                    // Jackson may parse a JSON array directly as a List when additionalInformation
                    // is deserialized from JDBC without a String-encoded wrapper.
                    String mappingsJson = JsonUtils.writeValueAsString(mappingsList);
                    claimMappings = JsonUtils.readValue(mappingsJson,
                            new TypeReference<List<TlsClientAuthConfiguration.ClaimMapping>>() {});
                }
                return new TlsClientAuthConfiguration(pem, claimMappings);
            } catch (Exception e) {
                return null;
            }
        }
        return null;
    }
}
