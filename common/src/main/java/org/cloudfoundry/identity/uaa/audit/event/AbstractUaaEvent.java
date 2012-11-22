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
package org.cloudfoundry.identity.uaa.audit.event;

import java.security.Principal;
import java.util.Map;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.UaaAuditService;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.map.annotate.JsonSerialize.Inclusion;
import org.springframework.context.ApplicationEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

/**
 * Base class for UAA events that want to publish audit records.
 * 
 * @author Luke Taylor
 * @author Dave Syer
 * 
 */
public abstract class AbstractUaaEvent extends ApplicationEvent {

	private static ObjectMapper mapper = new ObjectMapper();

	{
		mapper.setSerializationConfig(mapper.getSerializationConfig().withSerializationInclusion(Inclusion.NON_NULL));
	}

	protected AbstractUaaEvent(Object source) {
		super(source);
	}

	public void process(UaaAuditService auditor) {
		auditor.log(getAuditEvent());
	}

	protected AuditEvent createAuditRecord(String principalId, AuditEventType type, String origin) {
		return new AuditEvent(type, principalId, origin, null, System.currentTimeMillis());
	}

	protected AuditEvent createAuditRecord(String principalId, AuditEventType type, String origin, String data) {
		return new AuditEvent(type, principalId, origin, data, System.currentTimeMillis());
	}

	// Ideally we want to get to the point where details is never null, but this isn't currently possible
	// due to some OAuth authentication scenarios which don't set it.
	protected String getOrigin(Principal principal) {

		if (principal instanceof Authentication) {

			Authentication caller = (Authentication) principal;
			StringBuilder builder = new StringBuilder();
			if (caller instanceof OAuth2Authentication) {
				OAuth2Authentication oAuth2Authentication = (OAuth2Authentication) caller;
				builder.append("client=").append(oAuth2Authentication.getAuthorizationRequest().getClientId());
				if (!oAuth2Authentication.isClientOnly()) {
					builder.append(", ").append("user=").append(oAuth2Authentication.getName());
				}
			}
			else {
				builder.append("caller=").append(caller.getName()).append(", ");
			}

			if (caller.getDetails() != null) {
				builder.append(", details=(");
				try {
					@SuppressWarnings("unchecked")
					Map<String, Object> map = mapper.convertValue(caller.getDetails(), Map.class);
					if (map.containsKey("remoteAddress")) {
						builder.append("remoteAddress=").append(map.get("remoteAddress")).append(", ");
					}
					builder.append("type=").append(caller.getDetails().getClass().getSimpleName());
				}
				catch (Exception e) {
					// ignore
					builder.append(caller.getDetails());
				}
				builder.append(")");
			}
			return builder.toString();

		}

		return principal == null ? null : principal.getName();

	}

	public abstract AuditEvent getAuditEvent();

}
