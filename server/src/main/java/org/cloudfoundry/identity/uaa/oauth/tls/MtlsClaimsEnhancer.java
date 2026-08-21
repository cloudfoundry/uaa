package org.cloudfoundry.identity.uaa.oauth.tls;

import org.cloudfoundry.identity.uaa.client.TlsClientAuthConfiguration;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.ClientAuthentication;
import org.cloudfoundry.identity.uaa.oauth.UaaTokenEnhancer;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.UaaSecurityContextUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import tools.jackson.core.type.TypeReference;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
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

    private static final Pattern PLACEHOLDER = Pattern.compile("\\{([^}]++)\\}");

    /**
     * Bounds template length before it reaches {@link #PLACEHOLDER}'s regex -- see
     * {@link org.cloudfoundry.identity.uaa.client.ClientAdminEndpointsValidator}'s
     * {@code MAX_TEMPLATE_LENGTH} javadoc for the full rationale (same value, duplicated here
     * because the two classes are in different packages/modules; kept in sync by convention,
     * same as {@code PLACEHOLDER} itself). This guard is defense-in-depth for clients configured
     * via the BOSH-flat-config bootstrap path ({@link #loadTlsConfig}), which bypasses
     * ClientAdminEndpointsValidator's admin-API-time validation entirely.
     */
    static final int MAX_TEMPLATE_LENGTH = 256;

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
     * Returns an empty map when no certificate is present on the request, or when the client
     * did not actually authenticate via {@code tls_client_auth} (e.g. a client with both a
     * secret and TLS config configured that authenticated via {@code client_secret_basic} on
     * the mTLS alias) — the certificate mapped onto the request in that case was never
     * validated by {@link TlsClientAuthentication#validateClientCert}, so it must not be
     * trusted as a source of identity claims.
     */
    @Override
    public Map<String, Object> enhance(Map<String, Object> claims, OAuth2Authentication authentication) {
        // Cheap presence-only check (no trust decision, no database lookup) -- avoids resolving the
        // client's TlsClientAuthConfiguration at all when there is clearly nothing to process.
        if (!tlsClientAuthentication.hasCertificateFromRequest()) {
            return new HashMap<>();
        }

        if (!ClientAuthentication.TLS_CLIENT_AUTH.equals(
                UaaSecurityContextUtils.getClientAuthenticationMethod(authentication))) {
            return new HashMap<>();
        }

        String clientId = authentication.getOAuth2Request().getClientId();
        UaaClientDetails clientDetails = (UaaClientDetails) clientDetailsService.loadClientByClientId(clientId);

        // Check the typed field first (set directly on in-memory / admin-API clients);
        // fall back to additionalInformation for JDBC-loaded clients.
        TlsClientAuthConfiguration config = clientDetails.getTlsClientAuthConfiguration();
        if (config == null) {
            config = loadTlsConfig(clientDetails.getAdditionalInformation());
        }
        if (!TlsClientAuthConfiguration.isConfigured(config)) {
            return new HashMap<>();
        }

        // Now do the real, per-client trust decision: only a certificate validated against *this
        // client's* tls-client-auth-trusted-proxy-ca is used from here on.
        X509Certificate cert = tlsClientAuthentication.getCertificateFromRequest(config);
        if (cert == null) {
            return new HashMap<>();
        }

        // PHASE 1 — extract cert subject fields into vars (keyed by claim name)
        Map<String, String> vars = tlsClientAuthentication.extractClaimMappingValues(cert, config);

        // PHASE 2 — build JWT claims: dot-notation → nested object; flat → top-level
        Map<String, Object> result = new HashMap<>();
        Map<String, Map<String, Object>> nestedClaims = new HashMap<>();
        for (Map.Entry<String, String> entry : vars.entrySet()) {
            String key   = entry.getKey();
            String value = entry.getValue();
            // Only a single dot level is supported (spec: UAA-RFC8705-001 configurable-token-shape).
            // A key like "cf.app.id" would produce parent="cf", child="app.id" (not deeper nesting).
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
        } catch (CertificateEncodingException | NoSuchAlgorithmException e) {
            // Fail closed: an already-validated peer certificate should always be re-encodable,
            // and SHA-256 is a guaranteed JCE algorithm, so this is practically impossible. If it
            // ever happens, we must not silently issue an unbound bearer token in place of a
            // certificate-bound (RFC 8705 §3.1) one -- fail the whole token request instead (same
            // fail-closed philosophy as the client-details lookup failure above).
            throw new IllegalStateException(
                    "Failed to compute cnf.x5t#S256 confirmation claim for client_id="
                            + clientId + ": " + e.getMessage(), e);
        }

        // PHASE 3 — template rendering for sub and aud
        if (config.getSubTemplate() != null) {
            String rendered = renderTemplate(config.getSubTemplate(), vars);
            if (rendered != null) {
                result.put("sub", rendered);
            }
        }

        if (config.getAudTemplates() != null && !config.getAudTemplates().isEmpty()) {
            List<String> audList = new ArrayList<>();
            for (String tmpl : config.getAudTemplates()) {
                String rendered = renderTemplate(tmpl, vars);
                if (rendered != null) {
                    audList.add(rendered);
                }
            }
            if (!audList.isEmpty()) {
                result.put("aud", audList);
            }
        }

        return result;
    }

    /**
     * Renders a template string by substituting all {@code {varName}} placeholders
     * from {@code vars}. Returns {@code null} if any placeholder has no corresponding
     * value in {@code vars} (the whole template is then dropped by the caller).
     *
     * <p>Variable names may contain dots (e.g. {@code {cf.org}}); dots inside braces
     * are treated as part of the name, not as path separators.
     *
     * <p>Returns {@code null} without attempting to match if {@code template} exceeds
     * {@link #MAX_TEMPLATE_LENGTH}, treating an oversized template the same as an unresolvable
     * one (silently dropped by the caller) rather than a hard failure -- a hard failure here
     * would break every future token request for a client with a pre-existing, already-persisted
     * oversized template.
     */
    private String renderTemplate(String template, Map<String, String> vars) {
        if (template.length() > MAX_TEMPLATE_LENGTH) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        Matcher m = PLACEHOLDER.matcher(template);
        while (m.find()) {
            String varName = m.group(1);
            String value   = vars.get(varName);
            if (value == null) {
                return null;  // unresolved placeholder → caller should drop this template
            }
            m.appendReplacement(sb, Matcher.quoteReplacement(value));
        }
        m.appendTail(sb);
        return sb.toString();
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
                String subTemplate = null;
                Object rawSubTemplate = info.get(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUB_TEMPLATE);
                if (rawSubTemplate instanceof String st && !st.isBlank()) {
                    subTemplate = st;
                }

                List<String> audTemplates = null;
                Object rawAudTemplates = info.get(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_AUD_TEMPLATES);
                if (rawAudTemplates instanceof String audJson) {
                    audTemplates = JsonUtils.readValue(audJson, new TypeReference<List<String>>() {});
                } else if (rawAudTemplates instanceof List<?> audList) {
                    // Jackson may deserialise a JSON array as a List when additionalInformation
                    // is loaded from JDBC without a String-encoded wrapper.
                    audTemplates = JsonUtils.readValue(
                            JsonUtils.writeValueAsString(audList),
                            new TypeReference<List<String>>() {});
                }

                String trustedProxyCaPem = null;
                Object rawTrustedProxyCa = info.get(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_TRUSTED_PROXY_CA);
                if (rawTrustedProxyCa instanceof String tpc && !tpc.isBlank()) {
                    trustedProxyCaPem = tpc;
                }

                Map<String, String> requiredClaims = null;
                Object rawRequiredClaims = info.get(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_REQUIRED_CLAIMS);
                if (rawRequiredClaims instanceof String requiredClaimsJson) {
                    requiredClaims = JsonUtils.readValue(requiredClaimsJson,
                            new TypeReference<Map<String, String>>() {});
                } else if (rawRequiredClaims instanceof Map<?, ?> requiredClaimsMap) {
                    requiredClaims = JsonUtils.readValue(
                            JsonUtils.writeValueAsString(requiredClaimsMap),
                            new TypeReference<Map<String, String>>() {});
                }

                TlsClientAuthConfiguration cfg = new TlsClientAuthConfiguration(pem, claimMappings);
                cfg.setSubTemplate(subTemplate);
                cfg.setAudTemplates(audTemplates);
                cfg.setTrustedProxyCaPem(trustedProxyCaPem);
                cfg.setRequiredClaims(requiredClaims);
                return cfg;
            } catch (Exception e) {
                return null;
            }
        }
        return null;
    }
}
