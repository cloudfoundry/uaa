package org.cloudfoundry.identity.uaa.oauth.tls;

import org.cloudfoundry.identity.uaa.client.InvalidClientDetailsException;
import org.cloudfoundry.identity.uaa.client.TlsClientAuthConfiguration;
import org.cloudfoundry.identity.uaa.zone.MtlsResourcePolicy;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Map;

/** Resolves allowed resources only from the supplied zone configuration. */
public final class MtlsResourcePolicies {

    private static final String NAME_PATTERN = "[A-Za-z0-9][A-Za-z0-9._-]{0,127}";

    private MtlsResourcePolicies() {
    }

    public static void validate(Map<String, MtlsResourcePolicy> policies) {
        if (policies == null) {
            return;
        }
        policies.forEach((name, policy) -> {
            if (name == null || !name.matches(NAME_PATTERN)) {
                throw new InvalidClientDetailsException("Invalid mTLS resource policy name: " + name);
            }
            if (policy == null) {
                throw new InvalidClientDetailsException(
                        "Invalid mTLS resource policy '" + name + "': policy must not be null");
            }
            validateAllowedResources(
                    policy.getAllowedResources(), "mTLS resource policy '" + name + "'");
        });
    }

    public static List<String> resolve(
            Map<String, Object> info, Map<String, MtlsResourcePolicy> policies) {
        if (info == null) {
            return null;
        }
        String inlineKey = TlsClientAuthConfiguration.TLS_CLIENT_AUTH_ALLOWED_RESOURCES;
        String referenceKey = TlsClientAuthConfiguration.TLS_CLIENT_AUTH_ALLOWED_RESOURCES_REF;
        if (info.containsKey(inlineKey) && info.containsKey(referenceKey)) {
            throw new InvalidClientDetailsException(
                    inlineKey + " and " + referenceKey + " are mutually exclusive");
        }
        if (info.containsKey(referenceKey)) {
            if (!(info.get(referenceKey) instanceof String name) || name.isBlank()) {
                throw new InvalidClientDetailsException(
                        referenceKey + " must name a nonblank mTLS resource policy");
            }
            return resolve(name, policies);
        }
        List<String> allowedResources = TlsClientAuthConfigurationReader.readAllowedResources(info);
        if (allowedResources != null) {
            validateAllowedResources(allowedResources, inlineKey);
        }
        return allowedResources;
    }

    public static List<String> resolve(
            TlsClientAuthConfiguration config, Map<String, MtlsResourcePolicy> policies) {
        if (config == null) {
            return null;
        }
        if (config.getAllowedResources() != null && config.getAllowedResourcesRef() != null) {
            throw new InvalidClientDetailsException(
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_ALLOWED_RESOURCES + " and "
                            + TlsClientAuthConfiguration.TLS_CLIENT_AUTH_ALLOWED_RESOURCES_REF
                            + " are mutually exclusive");
        }
        if (config.getAllowedResourcesRef() != null) {
            if (config.getAllowedResourcesRef().isBlank()) {
                throw new InvalidClientDetailsException(
                        TlsClientAuthConfiguration.TLS_CLIENT_AUTH_ALLOWED_RESOURCES_REF
                                + " must name a nonblank mTLS resource policy");
            }
            return resolve(config.getAllowedResourcesRef(), policies);
        }
        if (config.getAllowedResources() != null) {
            validateAllowedResources(
                    config.getAllowedResources(),
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_ALLOWED_RESOURCES);
        }
        return config.getAllowedResources();
    }

    public static void validateAllowedResources(List<String> allowedResources, String propertyName) {
        if (allowedResources == null || allowedResources.isEmpty()) {
            throw new InvalidClientDetailsException(propertyName + " must not be empty");
        }
        for (String resource : allowedResources) {
            requireValidResourceIndicator(resource, propertyName);
        }
    }

    private static List<String> resolve(
            String name, Map<String, MtlsResourcePolicy> policies) {
        MtlsResourcePolicy policy = policies == null ? null : policies.get(name);
        if (policy == null) {
            throw new InvalidClientDetailsException(
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_ALLOWED_RESOURCES_REF
                            + ": unknown mTLS resource policy '" + name + "'");
        }
        validateAllowedResources(
                policy.getAllowedResources(), "mTLS resource policy '" + name + "'");
        return List.copyOf(policy.getAllowedResources());
    }

    /**
     * RFC 8707 section 2: resource indicators are absolute URIs without a fragment.
     */
    private static void requireValidResourceIndicator(String resource, String propertyName) {
        if (resource == null || resource.isBlank()) {
            throw new InvalidClientDetailsException(propertyName + " entry cannot be blank");
        }
        URI uri;
        try {
            uri = new URI(resource);
        } catch (URISyntaxException e) {
            throw new InvalidClientDetailsException(
                    propertyName + " entry '" + resource
                            + "' is not a valid URI (RFC 8707 section 2): " + e.getMessage(),
                    e);
        }
        if (!uri.isAbsolute()) {
            throw new InvalidClientDetailsException(
                    propertyName + " entry '" + resource
                            + "' must be an absolute URI (RFC 8707 section 2)");
        }
        if (uri.getFragment() != null) {
            throw new InvalidClientDetailsException(
                    propertyName + " entry '" + resource
                            + "' must not include a fragment component (RFC 8707 section 2)");
        }
    }
}
