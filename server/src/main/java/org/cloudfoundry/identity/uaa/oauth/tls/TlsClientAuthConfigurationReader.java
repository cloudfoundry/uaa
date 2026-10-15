package org.cloudfoundry.identity.uaa.oauth.tls;

import org.cloudfoundry.identity.uaa.client.TlsClientAuthConfiguration;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import tools.jackson.core.type.TypeReference;

import java.util.List;
import java.util.Map;

/**
 * Reads a client's {@link TlsClientAuthConfiguration} from the flat keys in its {@code additionalInformation}.
 *
 * <p>Client authentication and token enhancement must see the same configuration: the certificate a request
 * authenticates with depends on the proxy keys, and the token's {@code cnf} must describe that certificate.
 */
public final class TlsClientAuthConfigurationReader {

    private static final TypeReference<List<TlsClientAuthConfiguration.ClaimMapping>> CLAIM_MAPPINGS =
            new TypeReference<>() {};
    private static final TypeReference<List<String>> STRING_LIST = new TypeReference<>() {};
    private static final TypeReference<Map<String, String>> STRING_MAP = new TypeReference<>() {};

    private TlsClientAuthConfigurationReader() {
    }

    /**
     * @return the configuration, or {@code null} when the client is not configured for {@code tls_client_auth}
     * @throws IllegalArgumentException when the client carries mTLS keys that cannot be read. Such a client is
     *         mTLS-only and must not fall back to another authentication method.
     */
    public static TlsClientAuthConfiguration read(Map<String, Object> info) {
        if (info == null) {
            return null;
        }
        for (String referenceKey : List.of(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA_REF,
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_TRUSTED_PROXY_CA_REF)) {
            if (info.containsKey(referenceKey) && flatString(info, referenceKey) == null) {
                throw new IllegalArgumentException("tls_client_auth: " + referenceKey + " must name a nonblank trust bundle");
            }
        }
        // The key being present is what makes the client mTLS-only. A value that is blank or not a string -- a row
        // that bypassed registration validation -- must not turn it back into an ordinary client whose secret works.
        for (String inlineKey : List.of(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA,
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_TRUSTED_PROXY_CA,
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_TRUSTED_PROXY_SUBJECT_DN)) {
            if (info.containsKey(inlineKey) && flatString(info, inlineKey) == null) {
                throw new IllegalArgumentException("tls_client_auth: the client's " + inlineKey + " cannot be read");
            }
        }
        String pem = flatString(info, TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA);
        String caReference = flatString(info, TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA_REF);
        if (pem == null && caReference == null) {
            // Proxy trust also makes a client mTLS-only. Without workload trust it cannot authenticate at all.
            if (TlsClientAuthConfiguration.PROXY_TRUST_KEYS.stream().anyMatch(info::containsKey)) {
                throw new IllegalArgumentException(
                        "tls_client_auth: proxy trust requires tls-client-auth-ca or tls-client-auth-ca-ref");
            }
            return null;
        }
        try {
            TlsClientAuthConfiguration config = new TlsClientAuthConfiguration(pem,
                    json(info.get(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS), CLAIM_MAPPINGS));
            config.setTrustedCaRef(caReference);
            config.setTrustedProxyCaPem(flatString(info, TlsClientAuthConfiguration.TLS_CLIENT_AUTH_TRUSTED_PROXY_CA));
            config.setTrustedProxyCaRef(flatString(info, TlsClientAuthConfiguration.TLS_CLIENT_AUTH_TRUSTED_PROXY_CA_REF));
            config.setTrustedProxySubjectDn(
                    flatString(info, TlsClientAuthConfiguration.TLS_CLIENT_AUTH_TRUSTED_PROXY_SUBJECT_DN));
            config.setSubTemplate(flatString(info, TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUB_TEMPLATE));
            config.setAudTemplates(json(info.get(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_AUD_TEMPLATES), STRING_LIST));
            config.setRequiredClaims(json(info.get(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_REQUIRED_CLAIMS), STRING_MAP));
            config.setAllowedResources(
                    json(info.get(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_ALLOWED_RESOURCES), STRING_LIST));
            config.setSubjectDn(flatString(info, TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUBJECT_DN));
            config.setSanDns(flatString(info, TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_DNS));
            config.setSanUri(flatString(info, TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_URI));
            config.setSanIp(flatString(info, TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_IP));
            config.setSanEmail(flatString(info, TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_EMAIL));
            return config;
        } catch (RuntimeException e) {
            throw new IllegalArgumentException(
                    "tls_client_auth: the client's tls-client-auth configuration cannot be read", e);
        }
    }

    private static String flatString(Map<String, Object> info, String key) {
        return info.get(key) instanceof String value && !value.isBlank() ? value : null;
    }

    /** JDBC-loaded clients carry these values as JSON strings, others as already-parsed lists or maps. */
    private static <T> T json(Object raw, TypeReference<T> type) {
        if (raw instanceof String value) {
            return JsonUtils.readValue(value, type);
        }
        if (raw instanceof List<?> || raw instanceof Map<?, ?>) {
            return JsonUtils.readValue(JsonUtils.writeValueAsString(raw), type);
        }
        return null;
    }
}
