/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */
package org.cloudfoundry.identity.uaa.oauth.authz;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.error.ConvertingExceptionView;
import org.cloudfoundry.identity.uaa.error.ExceptionReport;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.message.SimpleMessage;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimException;
import org.cloudfoundry.identity.uaa.security.DefaultSecurityContextAccessor;
import org.cloudfoundry.identity.uaa.security.SecurityContextAccessor;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.View;

@Controller
public class ApprovalsAdminEndpoints implements InitializingBean {

	private ApprovalStore approvalStore;

	private ScimUserProvisioning usersManager;

	private Map<Class<? extends Exception>, HttpStatus> statuses = new HashMap<Class<? extends Exception>, HttpStatus>();

	private HttpMessageConverter<?>[] messageConverters = new RestTemplate().getMessageConverters().toArray(new HttpMessageConverter<?>[0]);

	private final Log logger = LogFactory.getLog(getClass());

	private SecurityContextAccessor securityContextAccessor = new DefaultSecurityContextAccessor();

	private static final String USER_FILTER_TEMPLATE = "userName eq '%s'";

	public void setStatuses(Map<Class<? extends Exception>, HttpStatus> statuses) {
		this.statuses = statuses;
	}

	public void setMessageConverters(HttpMessageConverter<?>[] messageConverters) {
		this.messageConverters = messageConverters;
	}

	public void setSecurityContextAccessor(SecurityContextAccessor securityContextAccessor) {
		this.securityContextAccessor = securityContextAccessor;
	}

	public void setApprovalStore(ApprovalStore approvalStore) {
		this.approvalStore = approvalStore;
	}

	public void setUsersManager(ScimUserProvisioning usersManager) {
		this.usersManager = usersManager;
	}

	@RequestMapping(value = "/approvals", method = RequestMethod.GET)
	@ResponseBody
	@PreAuthorize("@securityContextAccessor.isUser()")
	public List<Approval> getApprovals(@RequestParam(required = false, defaultValue = "userName pr") String filter,
													 @RequestParam(required = false, defaultValue = "1") int startIndex,
													 @RequestParam(required = false, defaultValue = "100") int count) {
		String username = getCurrentUsername();
		logger.debug("Fetching all approvals for user: " + username);
		return approvalStore.getApprovals(String.format("%s and " + USER_FILTER_TEMPLATE, filter, username))
				 .subList(startIndex - 1, startIndex + count - 1);
	}

	private String getCurrentUsername() {
		return usersManager.retrieveUser(securityContextAccessor.getUserId()).getUserName();
	}

	@RequestMapping(value = "/approvals", method = RequestMethod.PUT)
	@ResponseBody
	@PreAuthorize("@securityContextAccessor.isUser()")
	public List<Approval> updateApprovals(@RequestBody List approvals) {
		List<Approval> input;
		if (approvals.get(0) instanceof Approval) {
			input = approvals;
		} else {
			input = parseApprovalsJson(approvals);
		}

		String username = getCurrentUsername();
		logger.debug("Updating approvals for user: " + username);
		approvalStore.revokeApprovals(String.format(USER_FILTER_TEMPLATE, username));
		for (Approval approval : input) {
			if (!isValidUser(approval.getUserName())) {
				logger.warn(String.format("%s attemting to update approvals for %s", username, approval.getUserName()));
				throw new UaaException("unauthorized_operation", "Cannot update approvals for another user", HttpStatus.UNAUTHORIZED.value());
			}
			approvalStore.addApproval(approval);
		}
		return approvalStore.getApprovals(String.format(USER_FILTER_TEMPLATE, username));
	}

	private List<Approval> parseApprovalsJson (List approvals) {
		logger.info("approvals in JSON: " + approvals);

		List<Approval> response = new ArrayList<Approval>();
		for (Object approval : approvals) {
			Map<String, Object> app = (Map<String, Object>) approval;
			String userId = (String) app.get("userName");
			String clientId = (String) app.get("clientId");
			String scope = (String) app.get("scope");
			Date expiresAt = new Date(Long.parseLong(app.get("expiresAt").toString()));

			if (expiresAt.after(new Date())) {
				response.add(new Approval(userId, clientId, scope, expiresAt));
			}
		}
		return response;
	}

	private boolean isValidUser(String username) {
		List<ScimUser> users = usersManager.retrieveUsers(String.format(USER_FILTER_TEMPLATE, username));
		return users.size() == 1 && users.get(0).getId().equals(securityContextAccessor.getUserId());
	}

	@RequestMapping(value = "/approvals", method = RequestMethod.DELETE)
	@ResponseBody
	@PreAuthorize("@securityContextAccessor.isUser()")
	public SimpleMessage revokeApprovals() {
		String username = getCurrentUsername();
		logger.debug("Revoking all existing approvals for user: " + username);
		approvalStore.revokeApprovals(String.format(USER_FILTER_TEMPLATE, username));
		return new SimpleMessage("ok", "All approvals of current user revoked");
	}

	@ExceptionHandler
	public View handleException(Exception t) throws ScimException {
		UaaException e = t instanceof UaaException ? (UaaException) t : new UaaException("Unexpected error", "Error accessing user's approvals", HttpStatus.INTERNAL_SERVER_ERROR.value());
		Class<?> clazz = t.getClass();
		for (Class<?> key : statuses.keySet()) {
			if (key.isAssignableFrom(clazz)) {
				e = new UaaException(t.getMessage(), "Error accessing user's approvals", statuses.get(key).value());
				break;
			}
		}
		return new ConvertingExceptionView(new ResponseEntity<ExceptionReport>(new ExceptionReport(e, false),
								HttpStatus.valueOf(e.getHttpStatus())), messageConverters);
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(approvalStore, "Please supply an approvals manager");
		Assert.notNull(usersManager, "Please supply a users manager");
	}
}
