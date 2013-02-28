package org.cloudfoundry.identity.uaa.scim.security;

import java.util.Collection;

import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMembershipManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.web.FilterInvocation;
import org.springframework.util.StringUtils;

public class GroupVoter implements AccessDecisionVoter<Object> {

	private ScimGroupMembershipManager membershipManager;

	private String groupPrefix = "groupScope=";

	public void setGroupPrefix(String groupPrefix) {
		this.groupPrefix = groupPrefix;
	}

	public void setMembershipManager(ScimGroupMembershipManager membershipManager) {
		this.membershipManager = membershipManager;
	}

	@Override
	public boolean supports(ConfigAttribute attribute) {
		return (StringUtils.hasText(attribute.getAttribute()) && attribute.getAttribute().startsWith(groupPrefix));
	}

	@Override
	public boolean supports(Class<?> clazz) {
		return FilterInvocation.class.isAssignableFrom(clazz);
	}

	@Override
	public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {

		if (authentication instanceof OAuth2Authentication && ((OAuth2Authentication) authentication).isClientOnly()) {
			return ACCESS_ABSTAIN;
		}
		String userId = ((UaaPrincipal) authentication.getPrincipal()).getId();
		String groupId = getGroupId(((FilterInvocation) object).getRequestUrl());

		for (ConfigAttribute attribute : attributes) {
			if (this.supports(attribute)) {
				String requiredAuthority = attribute.getAttribute().substring(groupPrefix.length());
				if (membershipManager.getMembers(groupId, ScimGroupMember.Role.valueOf(requiredAuthority.toUpperCase())).contains(new ScimGroupMember(userId))) {
					return ACCESS_GRANTED;
				} else return ACCESS_DENIED;
			}
		}
		// no attribute supported by this voter
		return ACCESS_ABSTAIN;
	}

	private String getGroupId(String url) {
		int startIndex = url.lastIndexOf("/") + 1;
		int endIndex = url.indexOf("?") > 0 ? url.indexOf("?") : url.length();
		return url.substring(startIndex,  endIndex);
	}
}
