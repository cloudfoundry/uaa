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
package org.cloudfoundry.identity.uaa.user;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

/**
 * @author Dave Syer
 * 
 */
public class UaaUserApprovalHandler implements UserApprovalHandler {

    private Log logger = LogFactory.getLog(getClass());

    private boolean useTokenServices = true;

    private String approvalParameter = OAuth2Utils.USER_OAUTH_APPROVAL;

    private ClientDetailsService clientDetailsService;

    private OAuth2RequestFactory requestFactory;

    private AuthorizationServerTokenServices tokenServices;

    public void setTokenServices(AuthorizationServerTokenServices tokenServices) {
        this.tokenServices = tokenServices;
    }

    public void setRequestFactory(OAuth2RequestFactory requestFactory) {
        this.requestFactory = requestFactory;
    }

    public void setApprovalParameter(String approvalParameter) {
        this.approvalParameter = approvalParameter;
    }

    /**
     * @param clientDetailsService the clientDetailsService to set
     */
    public void setClientDetailsService(ClientDetailsService clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }

    /**
     * @param useTokenServices the useTokenServices to set
     */
    public void setUseTokenServices(boolean useTokenServices) {
        this.useTokenServices = useTokenServices;
    }

    /**
     * Allows automatic approval for a white list of clients in the implicit
     * grant case.
     * 
     * @param authorizationRequest The authorization request.
     * @param userAuthentication the current user authentication
     * 
     * @return Whether the specified request has been approved by the current
     *         user.
     */
    @Override
    public boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
//        if (useTokenServices && super.isApproved(authorizationRequest, userAuthentication)) {
//            return true;
//        }
        if (!userAuthentication.isAuthenticated()) {
            return false;
        }
        if (authorizationRequest.isApproved()) {
            return true;
        }
        String clientId = authorizationRequest.getClientId();
        boolean approved = false;
        if (clientDetailsService != null) {
            ClientDetails client = clientDetailsService.loadClientByClientId(clientId);
            Collection<String> requestedScopes = authorizationRequest.getScope();
            if (isAutoApprove(client, requestedScopes)) {
                approved = true;
            }
        }
        return approved;
    }

    private boolean isAutoApprove(ClientDetails client, Collection<String> scopes) {
        BaseClientDetails baseClient = (BaseClientDetails) client;
        if(baseClient.getAutoApproveScopes()!=null){
            if (baseClient.getAutoApproveScopes().contains("true")){
                return true;
            }
            if (baseClient.getAutoApproveScopes().containsAll(scopes)){
                return true;
            }
        }
        return false;
    }

    @Override
    public AuthorizationRequest checkForPreApproval(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
        boolean approved = false;

        String clientId = authorizationRequest.getClientId();
        Set<String> scopes = authorizationRequest.getScope();
        if (clientDetailsService!=null) {
            try {
                ClientDetails client = clientDetailsService.loadClientByClientId(clientId);
                approved = true;
                for (String scope : scopes) {
                    if (!client.isAutoApprove(scope)) {
                        approved = false;
                    }
                }
                if (approved) {
                    authorizationRequest.setApproved(true);
                    return authorizationRequest;
                }
            }
            catch (ClientRegistrationException e) {
                logger.warn("Client registration problem prevent autoapproval check for client=" + clientId);
            }
        }

        OAuth2Request storedOAuth2Request = requestFactory.createOAuth2Request(authorizationRequest);

        OAuth2Authentication authentication = new OAuth2Authentication(storedOAuth2Request, userAuthentication);
        if (logger.isDebugEnabled()) {
            StringBuilder builder = new StringBuilder("Looking up existing token for ");
            builder.append("client_id=" + clientId);
            builder.append(", scope=" + scopes);
            builder.append(" and username=" + userAuthentication.getName());
            logger.debug(builder.toString());
        }

        OAuth2AccessToken accessToken = tokenServices.getAccessToken(authentication);
        logger.debug("Existing access token=" + accessToken);
        if (accessToken != null && !accessToken.isExpired()) {
            logger.debug("User already approved with token=" + accessToken);
            // A token was already granted and is still valid, so this is already approved
            approved = true;
        }
        else {
            logger.debug("Checking explicit approval");
            approved = userAuthentication.isAuthenticated() && approved;
        }

        authorizationRequest.setApproved(approved);

        return authorizationRequest;
    }

    @Override
    public AuthorizationRequest updateAfterApproval(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
        Map<String, String> approvalParameters = authorizationRequest.getApprovalParameters();
        String flag = approvalParameters.get(approvalParameter);
        boolean approved = flag != null && flag.toLowerCase().equals("true");
        authorizationRequest.setApproved(approved);
        return authorizationRequest;
    }

    @Override
    public Map<String, Object> getUserApprovalRequest(AuthorizationRequest authorizationRequest,
                                                      Authentication userAuthentication) {
        Map<String, Object> model = new HashMap<String, Object>();
        // In case of a redirect we might want the request parameters to be included
        model.putAll(authorizationRequest.getRequestParameters());
        return model;
    }
}
