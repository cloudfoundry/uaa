package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.cloudfoundry.identity.uaa.oauth.provider.AuthorizationRequest;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.WebRequest;

import jakarta.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Controller for retrieving the model for and displaying the confirmation page
 * for access to a protected resource.
 */
@Controller
@SessionAttributes(UaaAuthorizationEndpoint.AUTHORIZATION_REQUEST)
public class AccessController {

    protected final Logger logger = LoggerFactory.getLogger(getClass());

    private static final String SCOPE_PREFIX = "scope.";

    private final MultitenantClientServices clientDetailsService;
    private final Boolean useSsl;
    private final ApprovalStore approvalStore;
    private final ScimGroupProvisioning groupProvisioning;

    /**
     * @param useSsl Explicitly requests caller to point back to an authorization endpoint on
     *               "https", even if the incoming request is "http"
     *               (e.g. when downstream of the SSL termination behind a load balancer).
     *               Always use HTTPS if deployed on cloudfoundry
     *               null to use the incoming request to determine the URL scheme
     */
    public AccessController(
            final @Qualifier("jdbcClientDetailsService") MultitenantClientServices clientDetailsService,
            final @Value("#{@applicationProperties['oauth.authorize.ssl']?:(T(java.lang.System).getenv('VCAP_APPLICATION')!=null ? true : null)}") Boolean useSsl,
            final @Qualifier("approvalStore") ApprovalStore approvalStore,
            final @Qualifier("scimGroupProvisioning") ScimGroupProvisioning groupProvisioning) {
        this.clientDetailsService = clientDetailsService;
        this.useSsl = useSsl;
        this.approvalStore = approvalStore;
        this.groupProvisioning = groupProvisioning;
    }

    @RequestMapping("/oauth/confirm_access")
    public String confirm(Map<String, Object> model, final HttpServletRequest request, Principal principal,
            SessionStatus sessionStatus) {

        if (!(principal instanceof Authentication)) {
            sessionStatus.setComplete();
            throw new InsufficientAuthenticationException(
                    "User must be authenticated with before authorizing access.");
        }

        AuthorizationRequest clientAuthRequest = (AuthorizationRequest) model.remove(UaaAuthorizationEndpoint.AUTHORIZATION_REQUEST);
        if (clientAuthRequest == null) {
            model.put("error",
                    "No authorization request is present, so we cannot confirm access (we don't know what you are asking for).");
        } else {
            String clientId = clientAuthRequest.getClientId();
            UaaClientDetails client = (UaaClientDetails) clientDetailsService.loadClientByClientId(clientId, IdentityZoneHolder.get().getId());
            UaaClientDetails modifiableClient = new UaaClientDetails(client);
            modifiableClient.setClientSecret(null);
            model.put("auth_request", clientAuthRequest);
            model.put("redirect_uri", getRedirectUri(modifiableClient, clientAuthRequest));

            Map<String, Object> additionalInfo = client.getAdditionalInformation();
            String clientDisplayName = (String) additionalInfo.get(ClientConstants.CLIENT_NAME);
            model.put("client_display_name", clientDisplayName != null ? clientDisplayName : clientId);

            // Find the auto approved scopes for this clients
            Set<String> autoApproved = client.getAutoApproveScopes();
            Set<String> autoApprovedScopes = new HashSet<>();
            if (autoApproved != null) {
                if (autoApproved.contains("true")) {
                    autoApprovedScopes.addAll(client.getScope());
                } else {
                    autoApprovedScopes.addAll(autoApproved);
                }
            }

            List<Approval> filteredApprovals = new ArrayList<>();
            // Remove auto approved scopes
            List<Approval> approvals = approvalStore.getApprovals(Origin.getUserId((Authentication) principal), clientId, IdentityZoneHolder.get().getId());
            for (Approval approval : approvals) {
                if (!autoApprovedScopes.contains(approval.getScope())) {
                    filteredApprovals.add(approval);
                }
            }

            ArrayList<String> approvedScopes = new ArrayList<>();
            ArrayList<String> deniedScopes = new ArrayList<>();

            for (Approval approval : filteredApprovals) {
                switch (approval.getStatus()) {
                    case APPROVED:
                        approvedScopes.add(approval.getScope());
                        break;
                    case DENIED:
                        deniedScopes.add(approval.getScope());
                        break;
                    default:
                        logger.error("Encountered an unknown scope. This is not supposed to happen");
                        break;
                }
            }

            ArrayList<String> undecidedScopes = new ArrayList<>();

            // Filter the scopes approved/denied from the ones requested
            for (String scope : clientAuthRequest.getScope()) {
                if (!approvedScopes.contains(scope) && !deniedScopes.contains(scope)
                        && !autoApprovedScopes.contains(scope)) {
                    undecidedScopes.add(scope);
                }
            }

            List<Map<String, String>> approvedScopeDetails = getScopes(approvedScopes);
            model.put("approved_scopes", approvedScopeDetails);
            List<Map<String, String>> undecidedScopeDetails = getScopes(undecidedScopes);
            model.put("undecided_scopes", undecidedScopeDetails);
            List<Map<String, String>> deniedScopeDetails = getScopes(deniedScopes);
            model.put("denied_scopes", deniedScopeDetails);

            List<Map<String, String>> allScopes = new ArrayList<>();
            allScopes.addAll(approvedScopeDetails);
            allScopes.addAll(undecidedScopeDetails);
            allScopes.addAll(deniedScopeDetails);

            model.put("scopes", allScopes);

            model.put("message",
                    "To confirm or deny access POST to the following locations with the parameters requested.");
            Map<String, Object> options = new HashMap<>() {
                {
                    put("confirm", new HashMap<String, String>() {
                        {
                            put("location", getLocation(request, "oauth/authorize"));
                            put("path", getPath(request, "oauth/authorize"));
                            put("key", OAuth2Utils.USER_OAUTH_APPROVAL);
                            put("value", "true");
                        }

                    });
                    put("deny", new HashMap<String, String>() {
                        {
                            put("location", getLocation(request, "oauth/authorize"));
                            put("path", getPath(request, "oauth/authorize"));
                            put("key", OAuth2Utils.USER_OAUTH_APPROVAL);
                            put("value", "false");
                        }

                    });
                }
            };
            model.put("options", options);
        }

        return "access_confirmation";

    }

    private List<Map<String, String>> getScopes(ArrayList<String> scopes) {

        List<Map<String, String>> result = new ArrayList<>();
        for (String scope : scopes) {
            HashMap<String, String> map = new HashMap<>();
            String code = SCOPE_PREFIX + scope;
            map.put("code", code);

            String zoneId = IdentityZoneHolder.get().getId();
            Optional<ScimGroup> group = Optional.of(groupProvisioning.getByName(scope, zoneId));
            group.ifPresent(g -> {
                String description = g.getDescription();
                if (StringUtils.hasText(description)) {
                    map.put("text", description);
                }
            });
            map.putIfAbsent("text", scope);

            result.add(map);
        }
        result.sort((map1, map2) -> {
            String code1 = map1.get("code");
            String code2 = map2.get("code");
            int i;
            if (0 != (i = codeIsPasswordOrOpenId(code2) - codeIsPasswordOrOpenId(code1))) {
                return i;
            }
            return code1.compareTo(code2);
        });
        return result;
    }

    private int codeIsPasswordOrOpenId(String code) {
        return code.startsWith(SCOPE_PREFIX + "password") || code.startsWith(SCOPE_PREFIX + "openid") ? 1 : 0;
    }

    private String getRedirectUri(ClientDetails client, AuthorizationRequest clientAuth) {
        String result = null;
        if (clientAuth.getRedirectUri() != null) {
            result = clientAuth.getRedirectUri();
        }
        if (client.getRegisteredRedirectUri() != null && !client.getRegisteredRedirectUri().isEmpty() && result == null) {
            result = client.getRegisteredRedirectUri().iterator().next();
        }
        if (result != null) {
            if (result.contains("?")) {
                result = result.substring(0, result.indexOf("?"));
            }
            if (result.contains("#")) {
                result = result.substring(0, result.indexOf("#"));
            }
        }
        return result;
    }

    @RequestMapping("/oauth/error")
    public String handleError(WebRequest request, Map<String, Object> model) {
        // There is already an error entry in the model
        Object object = request.getAttribute("error", RequestAttributes.SCOPE_REQUEST);
        if (object instanceof Exception e) {
            model.put("error_message", e.getMessage());
        }
        return "access_confirmation_error";
    }

    protected String getLocation(HttpServletRequest request, String path) {
        return extractScheme(request) + "://" + request.getHeader("Host") + getPath(request, path);
    }

    private String getPath(HttpServletRequest request, String path) {
        String contextPath = request.getContextPath();
        if (contextPath.endsWith("/")) {
            contextPath = contextPath.substring(0, contextPath.lastIndexOf("/") - 1);
        }
        if (path.startsWith("/")) {
            path = path.substring(1);
        }
        return contextPath + "/" + path;
    }

    protected String extractScheme(HttpServletRequest request) {
        return useSsl != null && useSsl ? "https" : request.getScheme();
    }
}
