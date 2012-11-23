package org.cloudfoundry.identity.uaa.oauth;

import java.security.Principal;
import java.util.Date;
import java.util.Map;

import org.cloudfoundry.identity.uaa.oauth.authz.Approval;
import org.cloudfoundry.identity.uaa.oauth.authz.ApprovalsManager;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.RedirectView;

@SessionAttributes("authorizationRequest")
@RequestMapping(value = "/oauth/authorize")
public class UserManagedAuthorizationEndpoint extends AuthorizationEndpoint {

	private ApprovalsManager approvalManager = null;

	@RequestMapping(method = RequestMethod.POST, params = AuthorizationRequest.USER_OAUTH_APPROVAL)
	public View approveOrDeny(@RequestParam Map<String, String> approvalParameters, Map<String, ?> model,
			SessionStatus sessionStatus, Principal principal) {
		//Process the approval
		View returnView = super.approveOrDeny(approvalParameters, (Map<String, ?>) model, sessionStatus, principal);
		
		//If everything's ok
		if (returnView instanceof RedirectView && ((RedirectView)returnView).getAttributesMap().containsKey("code")) {
			AuthorizationRequest authorizationRequest = (AuthorizationRequest) model.get("authorizationRequest");
			Date nextWeek = new Date(System.currentTimeMillis() + (86400 * 7 * 1000));
			
			//Store the approvals
			//TODO: Need error checking here
			for(String approvedScope : authorizationRequest.getScope()) {
				approvalManager.addApproval(new Approval(principal.getName(), authorizationRequest.getClientId(), approvedScope, nextWeek));
			}
		}
		
		return returnView;
	}

	public void setApprovalManager(ApprovalsManager approvalManager) {
		this.approvalManager = approvalManager;
	}
}
