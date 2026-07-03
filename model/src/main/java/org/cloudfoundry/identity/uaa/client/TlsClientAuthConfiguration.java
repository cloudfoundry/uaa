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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TlsClientAuthConfiguration that)) return false;
        return Objects.equals(trustedCaPem, that.trustedCaPem) &&
               Objects.equals(claimMappings, that.claimMappings) &&
               Objects.equals(subTemplate, that.subTemplate) &&
               Objects.equals(audTemplates, that.audTemplates) &&
               Objects.equals(trustedProxyCaPem, that.trustedProxyCaPem) &&
               Objects.equals(requiredClaims, that.requiredClaims);
    }

    @Override
    public int hashCode() {
        return Objects.hash(trustedCaPem, claimMappings, subTemplate, audTemplates, trustedProxyCaPem, requiredClaims);
    }

    public static boolean isConfigured(TlsClientAuthConfiguration config) {
        return config != null && config.getTrustedCaPem() != null && !config.getTrustedCaPem().isBlank();
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
