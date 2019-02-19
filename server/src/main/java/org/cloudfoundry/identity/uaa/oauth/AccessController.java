/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.oauth;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.zone.ClientServicesExtension;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.WebRequest;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Controller for retrieving the model for and displaying the confirmation page
 * for access to a protected resource.
 *
 * @author Dave Syer
 */
@Controller
@SessionAttributes("authorizationRequest")
public class AccessController {

    protected final Log logger = LogFactory.getLog(getClass());

    private static final String SCOPE_PREFIX = "scope.";

    private ClientServicesExtension clientDetailsService;

    private Boolean useSsl;

    private ApprovalStore approvalStore = null;

    private ScimGroupProvisioning groupProvisioning;

    /**
     * Explicitly requests caller to point back to an authorization endpoint on
     * "https", even if the incoming request is
     * "http" (e.g. when downstream of the SSL termination behind a load
     * balancer).
     *
     * @param useSsl the flag to set (null to use the incoming request to
     *            determine the URL scheme)
     */
    public void setUseSsl(Boolean useSsl) {
        this.useSsl = useSsl;
    }

    public void setClientDetailsService(ClientServicesExtension clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }

    public void setApprovalStore(ApprovalStore approvalStore) {
        this.approvalStore = approvalStore;
    }

    public ScimGroupProvisioning getGroupProvisioning() {
        return groupProvisioning;
    }

    public AccessController setGroupProvisioning(ScimGroupProvisioning groupProvisioning) {
        this.groupProvisioning = groupProvisioning;
        return this;
    }

    @RequestMapping("/oauth/confirm_access")
    public String confirm(Map<String, Object> model, final HttpServletRequest request, Principal principal,
                    SessionStatus sessionStatus) throws Exception {

        if (!(principal instanceof Authentication)) {
            sessionStatus.setComplete();
            throw new InsufficientAuthenticationException(
                            "User must be authenticated with before authorizing access.");
        }

        AuthorizationRequest clientAuthRequest = (AuthorizationRequest) model.remove("authorizationRequest");
        if (clientAuthRequest == null) {
            model.put("error",
                            "No authorization request is present, so we cannot confirm access (we don't know what you are asking for).");
        }
        else {
            String clientId = clientAuthRequest.getClientId();
            BaseClientDetails client = (BaseClientDetails) clientDetailsService.loadClientByClientId(clientId, IdentityZoneHolder.get().getId());
            BaseClientDetails modifiableClient = new BaseClientDetails(client);
            modifiableClient.setClientSecret(null);
            model.put("auth_request", clientAuthRequest);
            model.put("redirect_uri", getRedirectUri(modifiableClient, clientAuthRequest));

            Map<String, Object> additionalInfo = client.getAdditionalInformation();
            String clientDisplayName = (String) additionalInfo.get(ClientConstants.CLIENT_NAME);
            model.put("client_display_name", (clientDisplayName != null)? clientDisplayName : clientId);

            // Find the auto approved scopes for this clients
            Set<String> autoApproved = client.getAutoApproveScopes();
            Set<String> autoApprovedScopes = new HashSet<>();
            if (autoApproved != null) {
                if(autoApproved.contains("true")) {
                    autoApprovedScopes.addAll(client.getScope());
                } else {
                    autoApprovedScopes.addAll(autoApproved);
                }
            }

            List<Approval> filteredApprovals = new ArrayList<Approval>();
            // Remove auto approved scopes
            List<Approval> approvals = approvalStore.getApprovals(Origin.getUserId((Authentication)principal), clientId, IdentityZoneHolder.get().getId());
            for (Approval approval : approvals) {
                if (!(autoApprovedScopes.contains(approval.getScope()))) {
                    filteredApprovals.add(approval);
                }
            }

            ArrayList<String> approvedScopes = new ArrayList<String>();
            ArrayList<String> deniedScopes = new ArrayList<String>();

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

            ArrayList<String> undecidedScopes = new ArrayList<String>();

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
            Map<String, Object> options = new HashMap<String, Object>() {
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

        List<Map<String, String>> result = new ArrayList<Map<String, String>>();
        for (String scope : scopes) {
            HashMap<String, String> map = new HashMap<String, String>();
            String code = SCOPE_PREFIX + scope;
            map.put("code", code);

            Optional<ScimGroup> group = groupProvisioning.query(String.format("displayName eq \"%s\"", scope), IdentityZoneHolder.get().getId()).stream().findFirst();
            group.ifPresent(g -> {
                String description = g.getDescription();
                if (StringUtils.hasText(description)) {
                    map.put("text", description);
                }
            });
            map.putIfAbsent("text", scope);

            result.add(map);
        }
        Collections.sort(result, (map1, map2) -> {
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
    public String handleError(WebRequest request, Map<String, Object> model) throws Exception {
        // There is already an error entry in the model
        Object object = request.getAttribute("error", RequestAttributes.SCOPE_REQUEST);
        if (object != null) {
            model.put("error", object);
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
