package org.cloudfoundry.identity.uaa.oauth;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.oauth.authz.Approval;
import org.cloudfoundry.identity.uaa.oauth.authz.ApprovalsManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;

public class UserManagedAuthzApprovalHandler implements
		UserApprovalHandler {
	
	private static Log logger = LogFactory.getLog(UserManagedAuthzApprovalHandler.class);
	
	private String approvalParameter = AuthorizationRequest.USER_OAUTH_APPROVAL;

	private Collection<String> autoApproveClients = new HashSet<String>();

	private Map<String, Collection<String>> autoApproveClientScopes = new HashMap<String, Collection<String>>();
	
	private ApprovalsManager approvalManager = null;
	
	/**
	 * @param autoApproveClients the auto approve clients to set
	 */
	public void setAutoApproveClients(String[] autoApproveClients) {
		this.autoApproveClients = Arrays.asList(autoApproveClients);
	}

	public void setAutoApproveClientScopes(Map<String, Collection<String>> autoApproveClientScopes) {
		this.autoApproveClientScopes = autoApproveClientScopes;
		if (this.autoApproveClientScopes == null) {
			this.autoApproveClientScopes = Collections.emptyMap();
		}
	}

	@Override
	public AuthorizationRequest updateBeforeApproval(AuthorizationRequest authorizationRequest,	Authentication userAuthentication) {
		return authorizationRequest;
	}

	@Override
	public boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication) {
		
		String flag = authorizationRequest.getApprovalParameters().get(approvalParameter);
		boolean approved = flag != null && flag.toLowerCase().equals("true");

		if (logger.isDebugEnabled()) {
			StringBuilder builder = new StringBuilder("Looking up user approved authorizations for ");
			builder.append("client_id=" + authorizationRequest.getClientId());
			builder.append(" and username=" + userAuthentication.getName());
			logger.debug(builder.toString());
		}
		
		Collection<String> requestedScopes = authorizationRequest.getScope();

		if(!approved) {
			//Find the user in the authorizations table.
			List<Approval> userApprovals = 
					approvalManager.getApprovals(userAuthentication.getName(), 
													authorizationRequest.getClientId());
			
			//Look at the scopes and see if they have expired
			Set<String> validUserApprovedScopes = new HashSet<String>();
			Date today = new Date();
			for(Approval approval : userApprovals) {
				if(approval.getExpiresAt().after(today)) {
					validUserApprovedScopes.add(approval.getScope());
				}
			}

			if (logger.isDebugEnabled()) {
				logger.debug("Valid user approved scopes are " + validUserApprovedScopes);
			}
					
			//If the requested scopes have already been approved by the user, this request is approved
			if(validUserApprovedScopes.containsAll(requestedScopes) && userAuthentication.isAuthenticated()) {
				return true;
			}
			
		} else if(!authorizationRequest.getScope().isEmpty()) {
			//Store the scopes that have been approved
			Date nextWeek = new Date(System.currentTimeMillis() + (86400 * 7 * 1000));
			for(String approvedScope : authorizationRequest.getScope()) {
				approvalManager.addApproval(new Approval(userAuthentication.getName(),
															authorizationRequest.getClientId(),
															approvedScope,
															nextWeek));
			}
		}

		if (approved && userAuthentication.isAuthenticated()) {
			return true;
		}
		
		String clientId = authorizationRequest.getClientId();
		return authorizationRequest.isApproved()
				|| autoApproveClients.contains(clientId)
				|| (autoApproveClientScopes.containsKey(clientId) && autoApproveClientScopes.get(clientId).containsAll(requestedScopes));
	}

	public void setApprovalsManager(ApprovalsManager approvalManager) {
		this.approvalManager = approvalManager;
	}

}
