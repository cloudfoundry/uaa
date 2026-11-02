package org.cloudfoundry.identity.uaa.oauth.tls;

import org.cloudfoundry.identity.uaa.client.TlsClientAuthConfiguration;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import tools.jackson.core.type.TypeReference;

import java.util.List;
import java.util.Map;

/**
 * Reads a client's {@link TlsClientAuthConfiguration} from the flat {@code additionalInformation} map, which is how
 * clients loaded from the database and from the {@code oauth.clients} bootstrap carry it. List and map settings may
 * be stored as a JSON string or already parsed, depending on how the row was written.
 *
 * <p>Callers decide what an unreadable value means for them, so this class only reports it, as an
 * {@link IllegalArgumentException}.
 */
public final class TlsClientAuthConfigurationReader {

    private static final TypeReference<List<TlsClientAuthConfiguration.ClaimMapping>> CLAIM_MAPPINGS =
            new TypeReference<>() {};
    private static final TypeReference<List<String>> STRING_LIST = new TypeReference<>() {};
    private static final TypeReference<Map<String, String>> STRING_MAP = new TypeReference<>() {};

    private TlsClientAuthConfigurationReader() {
    }

    /**
     * @return the configuration, or {@code null} when neither {@code tls-client-auth-ca} nor
     *         {@code tls-client-auth-ca-ref} is a string
     * @throws IllegalArgumentException if a list or map setting cannot be read
     */
    public static TlsClientAuthConfiguration read(Map<String, Object> info) {
        if (info == null) {
            return null;
        }
        Object rawPem = info.get(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA);
        Object rawReference = info.get(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA_REF);
        if (!(rawPem instanceof String) && !(rawReference instanceof String)) {
            return null;
        }
        TlsClientAuthConfiguration cfg = new TlsClientAuthConfiguration(rawPem instanceof String pem ? pem : null,
                readJson(info.get(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS), CLAIM_MAPPINGS));
        cfg.setTrustedCaRef(flatString(info, TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA_REF));
        cfg.setTrustedProxyCaPem(flatString(info, TlsClientAuthConfiguration.TLS_CLIENT_AUTH_TRUSTED_PROXY_CA));
        cfg.setTrustedProxyCaRef(flatString(info, TlsClientAuthConfiguration.TLS_CLIENT_AUTH_TRUSTED_PROXY_CA_REF));
        cfg.setTrustedProxySubjectDn(flatString(info, TlsClientAuthConfiguration.TLS_CLIENT_AUTH_TRUSTED_PROXY_SUBJECT_DN));
        cfg.setSubTemplate(flatString(info, TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUB_TEMPLATE));
        cfg.setAudTemplates(readJson(info.get(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_AUD_TEMPLATES), STRING_LIST));
        cfg.setRequiredClaims(readJson(info.get(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_REQUIRED_CLAIMS), STRING_MAP));
        cfg.setAllowedResources(readAllowedResources(info));
        cfg.setSubjectDn(flatString(info, TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUBJECT_DN));
        cfg.setSanDns(flatString(info, TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_DNS));
        cfg.setSanUri(flatString(info, TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_URI));
        cfg.setSanIp(flatString(info, TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_IP));
        cfg.setSanEmail(flatString(info, TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_EMAIL));
        return cfg;
    }

    /**
     * @return {@code tls-client-auth-allowed-resources}, or {@code null} when absent
     * @throws IllegalArgumentException if the value cannot be read as a list of strings
     */
    public static List<String> readAllowedResources(Map<String, Object> info) {
        return info == null ? null
                : readJson(info.get(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_ALLOWED_RESOURCES), STRING_LIST);
    }

    /** A non-blank string value, or {@code null}. */
    private static String flatString(Map<String, Object> info, String key) {
        return info.get(key) instanceof String value && !value.isBlank() ? value : null;
    }

    private static <T> T readJson(Object raw, TypeReference<T> type) {
        if (raw == null) {
            return null;
        }
        try {
            String json = raw instanceof String text ? text : JsonUtils.writeValueAsString(raw);
            return JsonUtils.readValue(json, type);
        } catch (RuntimeException e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }
    }
}
