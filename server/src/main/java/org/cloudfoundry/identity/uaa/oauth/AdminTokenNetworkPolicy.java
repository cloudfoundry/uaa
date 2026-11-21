package org.cloudfoundry.identity.uaa.oauth;

import com.google.common.net.InetAddresses;
import jakarta.servlet.http.HttpServletRequest;
import org.cloudfoundry.identity.uaa.UaaProperties;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Operator-controlled, deployment-wide policy; tenant and client settings cannot relax it. */
public final class AdminTokenNetworkPolicy {
    private static final Logger LOGGER = LoggerFactory.getLogger(AdminTokenNetworkPolicy.class);
    private static final Set<String> ADMIN_SCOPES = Set.of(
            "uaa.admin", "cloud_controller.admin", "cloud_controller.admin_read_only",
            "cloud_controller.global_auditor");
    private final boolean enabled;
    private final List<Network> networks;
    private final Set<String> additionalProtectedScopes;

    public AdminTokenNetworkPolicy(UaaProperties.AdminTokenNetworkPolicy properties) {
        enabled = properties.enabled();
        networks = properties.allowed_cidrs().stream().map(Network::parse).toList();
        additionalProtectedScopes = Set.copyOf(properties.additional_protected_scopes());
    }

    /** Standalone instances default to disabled; Spring wiring always supplies the deployment policy. */
    public static AdminTokenNetworkPolicy disabled() {
        return new AdminTokenNetworkPolicy(new UaaProperties.AdminTokenNetworkPolicy(false, List.of(), List.of()));
    }

    public void checkIssuance(Collection<String> scopes, Collection<String> authorities) {
        HttpServletRequest request = RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes
                ? attributes.getRequest() : null;
        check(scopes, authorities, request);
    }

    public void checkClaims(Map<String, Object> claims) {
        checkIssuance(privileges(claims.get("scope")), privileges(claims.get("authorities")));
        checkIssuance(privileges(claims.get("granted_scopes")), List.of());
    }

    public void checkAuthentication(OAuth2Authentication authentication, HttpServletRequest request) {
        check(authentication.getOAuth2Request().getScope(),
                authentication.getAuthorities().stream().map(authority -> authority.getAuthority()).toList(), request);
    }

    private void check(Collection<String> scopes, Collection<String> authorities, HttpServletRequest request) {
        if (!enabled || !(protectedPrivileges(scopes) || protectedPrivileges(authorities))) {
            return;
        }
        // The servlet container establishes proxy trust. Never read forwarded headers or authentication details here.
        byte[] address = literal(request == null ? null : request.getRemoteAddr());
        if (address == null || networks.stream().noneMatch(network -> network.contains(address))) {
            LOGGER.warn("Administrative token network policy denied request");
            throw new AccessDeniedException("Administrative token source address is not allowed");
        }
    }

    private boolean protectedPrivileges(Collection<String> privileges) {
        return privileges != null && privileges.stream().anyMatch(privilege -> privilege != null && (
                ADMIN_SCOPES.contains(privilege) || additionalProtectedScopes.contains(privilege)
                        || privilege.matches("zones\\..+\\.admin")));
    }

    private static Collection<String> privileges(Object value) {
        if (value instanceof Collection<?> collection) {
            return collection.stream().filter(String.class::isInstance).map(String.class::cast).toList();
        }
        return value instanceof String text ? List.of(text.split("[ ,]+")) : List.of();
    }

    private static byte[] literal(String address) {
        if (address == null || address.contains("%")) {
            return null;
        }
        try {
            return InetAddresses.forString(address).getAddress();
        } catch (IllegalArgumentException _) {
            return null;
        }
    }

    private record Network(byte[] address, int prefix) {
        static Network parse(String cidr) {
            String[] parts = cidr.split("/", -1);
            byte[] address = literal(parts[0]);
            if (address == null || parts.length > 2 || (parts.length == 2 && (
                    !parts[1].matches("[0-9]{1,3}") || (parts[0].contains(":") && address.length == 4)))) {
                throw new IllegalArgumentException("Invalid administrative token allowed CIDR: " + cidr);
            }
            int prefix = parts.length == 1 ? address.length * 8 : Integer.parseInt(parts[1]);
            if (prefix > address.length * 8) {
                throw new IllegalArgumentException("Invalid administrative token allowed CIDR: " + cidr);
            }
            return new Network(address, prefix);
        }

        boolean contains(byte[] candidate) {
            if (candidate.length != address.length) {
                return false;
            }
            for (int bit = 0; bit < prefix; bit++) {
                int mask = 1 << (7 - bit % 8);
                if ((address[bit / 8] & mask) != (candidate[bit / 8] & mask)) {
                    return false;
                }
            }
            return true;
        }
    }
}
