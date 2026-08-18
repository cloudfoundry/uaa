package org.cloudfoundry.identity.uaa.oauth.tls;

import org.cloudfoundry.identity.uaa.client.TlsClientAuthConfiguration;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.ClientAuthentication;
import org.cloudfoundry.identity.uaa.oauth.UaaTokenEnhancer;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.UaaSecurityContextUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import tools.jackson.core.type.TypeReference;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
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
    private static final Pattern PLACEHOLDER = Pattern.compile("\\{([^}]+)\\}");

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
        X509Certificate cert = tlsClientAuthentication.getCertificateFromRequest();
        if (cert == null) {
            return new HashMap<>();
        }

        if (!ClientAuthentication.TLS_CLIENT_AUTH.equals(
                UaaSecurityContextUtils.getClientAuthenticationMethod(authentication))) {
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

        // Check the typed field first (set directly on in-memory / admin-API clients);
        // fall back to additionalInformation for JDBC-loaded clients.
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
            String cn  = extractRdnValue(dn, "CN");
            List<String> ous = extractOus(dn);

            for (TlsClientAuthConfiguration.ClaimMapping mapping : config.getClaimMappings()) {
                String value = switch (mapping.getField()) {
                    case "subject_cn" -> cn;
                    case "subject_ou" -> matchFirstOu(ous, mapping.getPattern());
                    case "subject_o"  -> extractRdnValue(dn, "O");
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
        } catch (Exception ignored) {
            // Silently skip cnf claim if cert encoding fails
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
     * Parses an RFC 2253 DN string into its RDNs, ordered most-specific-first
     * (i.e. matching the left-to-right order of the original DN string).
     *
     * <p>{@link LdapName#getRdns()} returns RDNs least-specific-first (root/rightmost
     * component at index 0), so the list is reversed here. Using {@link LdapName} instead
     * of a naive {@code dn.split(",")} correctly handles backslash-escaped commas/quotes
     * within attribute values (RFC 2253 §2.4), which a plain string split would mis-parse.
     * Returns an empty list if {@code dn} cannot be parsed as a valid DN.
     */
    private static List<Rdn> parseRdnsMostSpecificFirst(String dn) {
        try {
            List<Rdn> rdns = new ArrayList<>(new LdapName(dn).getRdns());
            Collections.reverse(rdns);
            return rdns;
        } catch (NamingException e) {
            return List.of();
        }
    }

    /**
     * Returns the value of the given attribute {@code type} (e.g. {@code "CN"}) from an RDN,
     * including multi-valued RDNs (attributes joined by {@code +}). Attribute type matching
     * is case-insensitive, per LDAP semantics. Returns {@code null} if not present.
     */
    private static String rdnAttributeValue(Rdn rdn, String type) {
        try {
            NamingEnumeration<? extends Attribute> attrs = rdn.toAttributes().getAll();
            while (attrs.hasMore()) {
                Attribute attr = attrs.next();
                if (attr.getID().equalsIgnoreCase(type)) {
                    Object value = attr.get();
                    return value == null ? null : value.toString();
                }
            }
        } catch (NamingException e) {
            // fall through to null
        }
        return null;
    }

    /**
     * Extracts the value of a single-valued RDN attribute (e.g. {@code "CN"}) from a RFC 2253
     * DN string. Handles multi-valued RDNs (attributes joined by {@code +}).
     * Returns {@code null} if no matching RDN is found.
     */
    private String extractRdnValue(String dn, String type) {
        for (Rdn rdn : parseRdnsMostSpecificFirst(dn)) {
            String value = rdnAttributeValue(rdn, type);
            if (value != null) {
                return value;
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
        for (Rdn rdn : parseRdnsMostSpecificFirst(dn)) {
            String value = rdnAttributeValue(rdn, "OU");
            if (value != null) {
                ous.add(value);
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
     * Renders a template string by substituting all {@code {varName}} placeholders
     * from {@code vars}. Returns {@code null} if any placeholder has no corresponding
     * value in {@code vars} (the whole template is then dropped by the caller).
     *
     * <p>Variable names may contain dots (e.g. {@code {cf.org}}); dots inside braces
     * are treated as part of the name, not as path separators.
     */
    private String renderTemplate(String template, Map<String, String> vars) {
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

                TlsClientAuthConfiguration cfg = new TlsClientAuthConfiguration(pem, claimMappings);
                cfg.setSubTemplate(subTemplate);
                cfg.setAudTemplates(audTemplates);
                return cfg;
            } catch (Exception e) {
                return null;
            }
        }
        return null;
    }
}
