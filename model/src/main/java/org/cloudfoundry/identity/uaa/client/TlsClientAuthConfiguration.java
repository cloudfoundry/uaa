package org.cloudfoundry.identity.uaa.client;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;
import java.util.Objects;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class TlsClientAuthConfiguration {

    public static final String TLS_CLIENT_AUTH_CA = "tls-client-auth-ca";
    public static final String TLS_CLIENT_AUTH_CLAIM_MAPPINGS = "tls-client-auth-claim-mappings";
    public static final String TLS_CLIENT_AUTH_SUB_TEMPLATE = "tls-client-auth-sub-template";
    public static final String TLS_CLIENT_AUTH_AUD_TEMPLATES = "tls-client-auth-aud-templates";
    public static final String TLS_CLIENT_AUTH_TRUSTED_PROXY_CA = "tls-client-auth-trusted-proxy-ca";
    public static final String TLS_CLIENT_AUTH_REQUIRED_CLAIMS = "tls-client-auth-required-claims";
    public static final String TLS_CLIENT_AUTH_ALLOW_ANY_CERT_FROM_CA = "tls-client-auth-allow-any-cert-from-ca";

    /**
     * Claim names a {@code tls-client-auth-claim-mappings} entry may not target.
     *
     * <p>Two groups. The first is UAA's own token vocabulary, which {@code UaaTokenServices} already
     * refuses to let an enhancer overwrite; rejecting those names at configuration time turns a
     * silently ignored mapping into an error the operator sees. The second is the group that was
     * genuinely reachable: authentication-context claims ({@code amr}, {@code acr},
     * {@code auth_time}, {@code client_auth_method}) and the RFC 8705 confirmation claim
     * ({@code cnf}). Those are not part of UAA's protected set, so a certificate subject field could
     * be mapped straight onto them -- letting a client admin assert, in a signed token, how the
     * caller authenticated. Downstream policy engines read exactly those claims.
     *
     * <p>{@code sub} and {@code aud} appear here as mapping targets only. They remain settable
     * through {@code tls-client-auth-sub-template} / {@code tls-client-auth-aud-templates}, which is
     * the supported, placeholder-checked path for them.
     */
    public static final java.util.Set<String> RESERVED_CLAIM_NAMES = java.util.Set.of(
            // UAA-owned token vocabulary
            "jti", "sub", "aud", "iss", "exp", "iat", "nbf", "zid",
            "scope", "granted_scopes", "authorities", "client_id", "cid", "azp",
            "grant_type", "user_id", "user_name", "origin", "email", "revocable",
            "rev_sig", "previous_logon_time",
            // authentication context and certificate binding
            "amr", "acr", "auth_time", "cnf", "client_auth_method");

    /**
     * True when {@code claim} is itself a reserved name, or when it is a dotted claim (e.g.
     * {@code "sub.foo"}) whose first segment is reserved.
     *
     * <p>{@code MtlsClaimsEnhancer}'s dot-notation nesting turns a mapping named {@code "sub.foo"}
     * into a nested {@code {"foo": ...}} object stored under the top-level claim {@code "sub"} --
     * an exact-name check against {@code RESERVED_CLAIM_NAMES} does not catch this, because the
     * dotted claim name itself is not in the set, only its parent is. That nested object then
     * overwrites the real {@code sub}/{@code aud} value in {@code UaaTokenServices}, producing a
     * JWT whose {@code sub}/{@code aud} is an object rather than the RFC 7519 string/string-array
     * it must be.
     */
    public static boolean isReservedClaimName(String claim) {
        if (claim == null) {
            return false;
        }
        int dotIdx = claim.indexOf('.');
        String root = dotIdx >= 0 ? claim.substring(0, dotIdx) : claim;
        return RESERVED_CLAIM_NAMES.contains(root);
    }

    @JsonProperty(TLS_CLIENT_AUTH_CA)
    private String trustedCaPem;

    @JsonProperty(TLS_CLIENT_AUTH_CLAIM_MAPPINGS)
    private List<ClaimMapping> claimMappings;

    @JsonProperty(TLS_CLIENT_AUTH_SUB_TEMPLATE)
    private String subTemplate;

    @JsonProperty(TLS_CLIENT_AUTH_AUD_TEMPLATES)
    private List<String> audTemplates;

    @JsonProperty(TLS_CLIENT_AUTH_TRUSTED_PROXY_CA)
    private String trustedProxyCaPem;

    @JsonProperty(TLS_CLIENT_AUTH_REQUIRED_CLAIMS)
    private Map<String, String> requiredClaims;

    @JsonProperty(TLS_CLIENT_AUTH_ALLOW_ANY_CERT_FROM_CA)
    private boolean allowAnyCertFromCa;

    public TlsClientAuthConfiguration() {}

    public TlsClientAuthConfiguration(String trustedCaPem, List<ClaimMapping> claimMappings) {
        this.trustedCaPem = trustedCaPem;
        this.claimMappings = claimMappings;
    }

    public String getTrustedCaPem() { return trustedCaPem; }
    public void setTrustedCaPem(String trustedCaPem) { this.trustedCaPem = trustedCaPem; }

    public List<ClaimMapping> getClaimMappings() { return claimMappings; }
    public void setClaimMappings(List<ClaimMapping> claimMappings) { this.claimMappings = claimMappings; }

    public String getSubTemplate() { return subTemplate; }
    public void setSubTemplate(String subTemplate) { this.subTemplate = subTemplate; }

    public List<String> getAudTemplates() { return audTemplates; }
    public void setAudTemplates(List<String> audTemplates) { this.audTemplates = audTemplates; }

    public String getTrustedProxyCaPem() { return trustedProxyCaPem; }
    public void setTrustedProxyCaPem(String trustedProxyCaPem) { this.trustedProxyCaPem = trustedProxyCaPem; }

    public Map<String, String> getRequiredClaims() { return requiredClaims; }
    public void setRequiredClaims(Map<String, String> requiredClaims) { this.requiredClaims = requiredClaims; }

    public boolean isAllowAnyCertFromCa() { return allowAnyCertFromCa; }
    public void setAllowAnyCertFromCa(boolean allowAnyCertFromCa) { this.allowAnyCertFromCa = allowAnyCertFromCa; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TlsClientAuthConfiguration that)) return false;
        return Objects.equals(trustedCaPem, that.trustedCaPem) &&
               Objects.equals(claimMappings, that.claimMappings) &&
               Objects.equals(subTemplate, that.subTemplate) &&
               Objects.equals(audTemplates, that.audTemplates) &&
               Objects.equals(trustedProxyCaPem, that.trustedProxyCaPem) &&
               Objects.equals(requiredClaims, that.requiredClaims) &&
               allowAnyCertFromCa == that.allowAnyCertFromCa;
    }

    @Override
    public int hashCode() {
        return Objects.hash(trustedCaPem, claimMappings, subTemplate, audTemplates, trustedProxyCaPem,
                requiredClaims, allowAnyCertFromCa);
    }

    public static boolean isConfigured(TlsClientAuthConfiguration config) {
        return config != null && config.getTrustedCaPem() != null && !config.getTrustedCaPem().isBlank();
    }

    /**
     * Whether this client's configuration ties a presented certificate to <em>this</em> client,
     * rather than accepting any certificate the configured CA ever issued.
     *
     * <p>PKIX validation against {@code tls-client-auth-ca} only proves "issued by that CA". Where
     * the CA is shared -- and the headline use case, Cloud Foundry's Diego instance-identity CA, is
     * shared across every app instance in the foundation -- that is not an identity for this client:
     * any holder of any certificate from that CA would authenticate as this client. RFC 8705
     * section 2.1.2 therefore requires the authorization server to compare a configured subject
     * value against the presented certificate.
     *
     * <p>{@code tls-client-auth-required-claims} is that comparison. A client that deliberately
     * wants CA-issuance alone to be sufficient -- e.g. a dedicated single-purpose CA, where the CA
     * itself is the binding -- must say so explicitly via
     * {@code tls-client-auth-allow-any-cert-from-ca}, so the decision is recorded in configuration
     * instead of being the silent default.
     */
    public static boolean hasSubjectBinding(TlsClientAuthConfiguration config) {
        if (config == null) {
            return false;
        }
        return config.isAllowAnyCertFromCa()
                || (config.getRequiredClaims() != null && !config.getRequiredClaims().isEmpty());
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ClaimMapping {

        @JsonProperty("field")
        private String field;

        @JsonProperty("pattern")
        private String pattern;

        @JsonProperty("claim")
        private String claim;

        public ClaimMapping() {}

        public ClaimMapping(String field, String pattern, String claim) {
            this.field = field;
            this.pattern = pattern;
            this.claim = claim;
        }

        public String getField()   { return field; }
        public String getPattern() { return pattern; }
        public String getClaim()   { return claim; }

        public void setField(String field)     { this.field = field; }
        public void setPattern(String pattern) { this.pattern = pattern; }
        public void setClaim(String claim)     { this.claim = claim; }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof ClaimMapping that)) return false;
            return Objects.equals(field, that.field) &&
                   Objects.equals(pattern, that.pattern) &&
                   Objects.equals(claim, that.claim);
        }

        @Override
        public int hashCode() {
            return Objects.hash(field, pattern, claim);
        }
    }
}
