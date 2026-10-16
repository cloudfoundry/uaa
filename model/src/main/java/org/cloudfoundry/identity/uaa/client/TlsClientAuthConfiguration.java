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
    public static final String TLS_CLIENT_AUTH_CA_REF = "tls-client-auth-ca-ref";
    public static final String TLS_CLIENT_AUTH_TRUSTED_PROXY_CA_REF = "tls-client-auth-trusted-proxy-ca-ref";
    public static final String TLS_CLIENT_AUTH_CLAIM_MAPPINGS = "tls-client-auth-claim-mappings";
    public static final String TLS_CLIENT_AUTH_SUB_TEMPLATE = "tls-client-auth-sub-template";
    public static final String TLS_CLIENT_AUTH_AUD_TEMPLATES = "tls-client-auth-aud-templates";
    public static final String TLS_CLIENT_AUTH_TRUSTED_PROXY_CA = "tls-client-auth-trusted-proxy-ca";
    public static final String TLS_CLIENT_AUTH_TRUSTED_PROXY_SUBJECT_DN = "tls-client-auth-trusted-proxy-subject-dn";
    public static final String TLS_CLIENT_AUTH_REQUIRED_CLAIMS = "tls-client-auth-required-claims";

    /**
     * RFC 8707 resource indicators: the exact {@code resource} values a client may request at the
     * mTLS token endpoint. Mutually exclusive with {@link #TLS_CLIENT_AUTH_AUD_TEMPLATES} -- two
     * mechanisms for setting {@code aud} on one client is a footgun -- and, unlike the templates,
     * requires no certificate-derived value: the client names the resource itself, and this list is
     * what the server is willing to believe it may ask for.
     */
    public static final String TLS_CLIENT_AUTH_ALLOWED_RESOURCES = "tls-client-auth-allowed-resources";

    /**
     * RFC 8705 section 3.4 client registration metadata, named verbatim like the subject parameters
     * below. {@code true} makes the access tokens issued to the client certificate-bound
     * ({@code cnf.x5t#S256}); {@code false} or absent -- the RFC default -- issues an ordinary
     * bearer JWT. It is independent of {@code tls_client_auth}: authenticating with a certificate
     * does not by itself require a bound token (RFC 8705 section 1). Registration-only: a token
     * request cannot change it.
     */
    public static final String TLS_CLIENT_CERTIFICATE_BOUND_ACCESS_TOKENS = "tls_client_certificate_bound_access_tokens";

    /** RFC 8707 section 2's token-request parameter name, distinct from the config keys above. */
    public static final String RESOURCE_PARAMETER = "resource";

    /**
     * RFC 8705 section 2.1.2 client registration metadata: the expected certificate subject value.
     *
     * <p>These use the IANA-registered parameter names verbatim (underscores, not UAA's usual
     * hyphenated style) so that metadata from an RFC 7591 dynamic client registration is accepted
     * unchanged. A client using {@code tls_client_auth} MUST use exactly one of them -- chain
     * validation establishes only that some certificate from the configured CA was presented, and
     * the subject value is what identifies <em>this</em> client.
     */
    public static final String TLS_CLIENT_AUTH_SUBJECT_DN = "tls_client_auth_subject_dn";
    public static final String TLS_CLIENT_AUTH_SAN_DNS = "tls_client_auth_san_dns";
    public static final String TLS_CLIENT_AUTH_SAN_URI = "tls_client_auth_san_uri";
    public static final String TLS_CLIENT_AUTH_SAN_IP = "tls_client_auth_san_ip";
    public static final String TLS_CLIENT_AUTH_SAN_EMAIL = "tls_client_auth_san_email";

    /** The five RFC 8705 section 2.1.2 subject parameters, in the order the RFC lists them. */
    public static final List<String> SUBJECT_BINDING_PARAMETERS = List.of(
            TLS_CLIENT_AUTH_SUBJECT_DN,
            TLS_CLIENT_AUTH_SAN_DNS,
            TLS_CLIENT_AUTH_SAN_URI,
            TLS_CLIENT_AUTH_SAN_IP,
            TLS_CLIENT_AUTH_SAN_EMAIL);

    /**
     * Settings that only apply to certificate authentication: the subject binding, claim mappings, templates,
     * required claims and allowed resources. Each requires workload trust ({@link #TLS_CLIENT_AUTH_CA} or
     * {@link #TLS_CLIENT_AUTH_CA_REF}); without it they would be stored and silently ignored.
     */
    public static final List<String> CERTIFICATE_ONLY_SETTING_KEYS = List.of(
            TLS_CLIENT_AUTH_SUBJECT_DN,
            TLS_CLIENT_AUTH_SAN_DNS,
            TLS_CLIENT_AUTH_SAN_URI,
            TLS_CLIENT_AUTH_SAN_IP,
            TLS_CLIENT_AUTH_SAN_EMAIL,
            TLS_CLIENT_AUTH_CLAIM_MAPPINGS,
            TLS_CLIENT_AUTH_SUB_TEMPLATE,
            TLS_CLIENT_AUTH_AUD_TEMPLATES,
            TLS_CLIENT_AUTH_REQUIRED_CLAIMS,
            TLS_CLIENT_AUTH_ALLOWED_RESOURCES);

    /** Keys that configure the proxy allowed to forward a client certificate. Each requires workload trust. */
    public static final List<String> PROXY_TRUST_KEYS = List.of(
            TLS_CLIENT_AUTH_TRUSTED_PROXY_CA,
            TLS_CLIENT_AUTH_TRUSTED_PROXY_CA_REF,
            TLS_CLIENT_AUTH_TRUSTED_PROXY_SUBJECT_DN);

    /**
     * Claim names a {@code tls-client-auth-claim-mappings} entry may not target.
     *
     * <p>Two groups. The first is UAA's own token vocabulary, which {@code UaaTokenServices} already
     * refuses to let an enhancer overwrite; rejecting those names at configuration time turns a
     * silently ignored mapping into an error the operator sees. The second is the group that was
     * reachable: authentication-context claims ({@code amr}, {@code acr},
     * {@code auth_time}, {@code client_auth_method}) and the RFC 8705 confirmation claim
     * ({@code cnf}), plus delegation context ({@code act}, {@code may_act}). Those are not part of
     * UAA's protected set, so a certificate subject field could
     * be mapped straight onto them -- letting a client admin assert, in a signed token, how the
     * caller authenticated or who may act on its behalf. Downstream policy engines read these claims.
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
            "amr", "acr", "auth_time", "cnf", "client_auth_method",
            // delegation context must come from token exchange, never from certificate mappings
            "act", "may_act");

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

    /**
     * Reads {@link #TLS_CLIENT_CERTIFICATE_BOUND_ACCESS_TOKENS} from a client's flat configuration:
     * a {@link Boolean} or the string {@code true}/{@code false} (any case, as BOSH/YAML bootstrap
     * and JSON registration both produce). Absent is {@code false}, the RFC 8705 section 3.4 default.
     * Anything else is {@code null}, so registration and issuance can refuse an unreadable policy
     * instead of silently issuing a bearer token.
     */
    public static Boolean parseBoundAccessTokens(Object raw) {
        if (raw == null) {
            return Boolean.FALSE;
        }
        if (raw instanceof Boolean bool) {
            return bool;
        }
        if (raw instanceof String text) {
            if ("true".equalsIgnoreCase(text)) {
                return Boolean.TRUE;
            }
            if ("false".equalsIgnoreCase(text)) {
                return Boolean.FALSE;
            }
        }
        return null;
    }

    /**
     * The address bytes of an IPv4 or IPv6 <em>literal</em>, or {@code null} when {@code value} is anything
     * else, a hostname included. The character check comes first so that
     * {@link java.net.InetAddress#getByName} is only ever handed text it parses as a literal: it falls back
     * to a DNS lookup for anything that does not look like one, and a client's registered
     * {@code tls_client_auth_san_ip} must not make authentication depend on name resolution.
     */
    public static byte[] parseIpLiteral(String value) {
        if (value == null) {
            return null;
        }
        boolean ipv6 = value.indexOf(':') >= 0;
        boolean valid = ipv6
                ? value.matches("[0-9A-Fa-f:.]+")
                : value.matches("\\d{1,3}(\\.\\d{1,3}){3}");
        if (!valid) {
            return null;
        }
        try {
            return java.net.InetAddress.getByName(value).getAddress();
        } catch (java.net.UnknownHostException e) {
            return null;
        }
    }

    @JsonProperty(TLS_CLIENT_AUTH_CA)
    private String trustedCaPem;

    @JsonProperty(TLS_CLIENT_AUTH_CA_REF)
    private String trustedCaRef;

    @JsonProperty(TLS_CLIENT_AUTH_TRUSTED_PROXY_CA_REF)
    private String trustedProxyCaRef;

    @JsonProperty(TLS_CLIENT_AUTH_CLAIM_MAPPINGS)
    private List<ClaimMapping> claimMappings;

    @JsonProperty(TLS_CLIENT_AUTH_SUB_TEMPLATE)
    private String subTemplate;

    @JsonProperty(TLS_CLIENT_AUTH_AUD_TEMPLATES)
    private List<String> audTemplates;

    @JsonProperty(TLS_CLIENT_AUTH_TRUSTED_PROXY_CA)
    private String trustedProxyCaPem;

    @JsonProperty(TLS_CLIENT_AUTH_TRUSTED_PROXY_SUBJECT_DN)
    private String trustedProxySubjectDn;

    @JsonProperty(TLS_CLIENT_AUTH_REQUIRED_CLAIMS)
    private Map<String, String> requiredClaims;

    @JsonProperty(TLS_CLIENT_AUTH_ALLOWED_RESOURCES)
    private List<String> allowedResources;

    @JsonProperty(TLS_CLIENT_AUTH_SUBJECT_DN)
    private String subjectDn;

    @JsonProperty(TLS_CLIENT_AUTH_SAN_DNS)
    private String sanDns;

    @JsonProperty(TLS_CLIENT_AUTH_SAN_URI)
    private String sanUri;

    @JsonProperty(TLS_CLIENT_AUTH_SAN_IP)
    private String sanIp;

    @JsonProperty(TLS_CLIENT_AUTH_SAN_EMAIL)
    private String sanEmail;

    public TlsClientAuthConfiguration() {}

    public TlsClientAuthConfiguration(String trustedCaPem, List<ClaimMapping> claimMappings) {
        this.trustedCaPem = trustedCaPem;
        this.claimMappings = claimMappings;
    }

    public String getTrustedCaPem() { return trustedCaPem; }
    public String getTrustedCaRef() { return trustedCaRef; }
    public void setTrustedCaRef(String trustedCaRef) { this.trustedCaRef = trustedCaRef; }
    public String getTrustedProxyCaRef() { return trustedProxyCaRef; }
    public void setTrustedProxyCaRef(String trustedProxyCaRef) { this.trustedProxyCaRef = trustedProxyCaRef; }
    public void setTrustedCaPem(String trustedCaPem) { this.trustedCaPem = trustedCaPem; }

    public List<ClaimMapping> getClaimMappings() { return claimMappings; }
    public void setClaimMappings(List<ClaimMapping> claimMappings) { this.claimMappings = claimMappings; }

    public String getSubTemplate() { return subTemplate; }
    public void setSubTemplate(String subTemplate) { this.subTemplate = subTemplate; }

    public List<String> getAudTemplates() { return audTemplates; }
    public void setAudTemplates(List<String> audTemplates) { this.audTemplates = audTemplates; }

    public String getTrustedProxyCaPem() { return trustedProxyCaPem; }
    public void setTrustedProxyCaPem(String trustedProxyCaPem) { this.trustedProxyCaPem = trustedProxyCaPem; }
    public String getTrustedProxySubjectDn() { return trustedProxySubjectDn; }
    public void setTrustedProxySubjectDn(String trustedProxySubjectDn) { this.trustedProxySubjectDn = trustedProxySubjectDn; }

    public Map<String, String> getRequiredClaims() { return requiredClaims; }
    public void setRequiredClaims(Map<String, String> requiredClaims) { this.requiredClaims = requiredClaims; }

    public List<String> getAllowedResources() { return allowedResources; }
    public void setAllowedResources(List<String> allowedResources) { this.allowedResources = allowedResources; }

    public String getSubjectDn() { return subjectDn; }
    public void setSubjectDn(String subjectDn) { this.subjectDn = subjectDn; }

    public String getSanDns() { return sanDns; }
    public void setSanDns(String sanDns) { this.sanDns = sanDns; }

    public String getSanUri() { return sanUri; }
    public void setSanUri(String sanUri) { this.sanUri = sanUri; }

    public String getSanIp() { return sanIp; }
    public void setSanIp(String sanIp) { this.sanIp = sanIp; }

    public String getSanEmail() { return sanEmail; }
    public void setSanEmail(String sanEmail) { this.sanEmail = sanEmail; }

    /**
     * The RFC 8705 section 2.1.2 subject parameters this configuration actually sets, by parameter
     * name. The spec requires exactly one; returning them all lets callers report "none" and "more
     * than one" distinctly.
     */
    public List<String> configuredSubjectBindings() {
        List<String> configured = new java.util.ArrayList<>();
        addIfPresent(configured, TLS_CLIENT_AUTH_SUBJECT_DN, subjectDn);
        addIfPresent(configured, TLS_CLIENT_AUTH_SAN_DNS, sanDns);
        addIfPresent(configured, TLS_CLIENT_AUTH_SAN_URI, sanUri);
        addIfPresent(configured, TLS_CLIENT_AUTH_SAN_IP, sanIp);
        addIfPresent(configured, TLS_CLIENT_AUTH_SAN_EMAIL, sanEmail);
        return configured;
    }

    private static void addIfPresent(List<String> target, String name, String value) {
        if (value != null && !value.isBlank()) {
            target.add(name);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TlsClientAuthConfiguration that)) return false;
        return Objects.equals(trustedCaPem, that.trustedCaPem) &&
               Objects.equals(trustedCaRef, that.trustedCaRef) &&
               Objects.equals(trustedProxyCaRef, that.trustedProxyCaRef) &&
               Objects.equals(claimMappings, that.claimMappings) &&
               Objects.equals(subTemplate, that.subTemplate) &&
               Objects.equals(audTemplates, that.audTemplates) &&
               Objects.equals(trustedProxyCaPem, that.trustedProxyCaPem) &&
               Objects.equals(trustedProxySubjectDn, that.trustedProxySubjectDn) &&
               Objects.equals(requiredClaims, that.requiredClaims) &&
               Objects.equals(subjectDn, that.subjectDn) &&
               Objects.equals(sanDns, that.sanDns) &&
               Objects.equals(sanUri, that.sanUri) &&
               Objects.equals(sanIp, that.sanIp) &&
               Objects.equals(sanEmail, that.sanEmail) &&
               Objects.equals(allowedResources, that.allowedResources);
    }

    @Override
    public int hashCode() {
        return Objects.hash(trustedCaPem, trustedCaRef, trustedProxyCaRef, claimMappings, subTemplate, audTemplates, trustedProxyCaPem,
                trustedProxySubjectDn, requiredClaims, subjectDn, sanDns, sanUri, sanIp, sanEmail, allowedResources);
    }

    public static boolean isConfigured(TlsClientAuthConfiguration config) {
        return config != null && ((config.getTrustedCaPem() != null && !config.getTrustedCaPem().isBlank())
                || (config.getTrustedCaRef() != null && !config.getTrustedCaRef().isBlank()));
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
