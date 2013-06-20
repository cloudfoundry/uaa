package org.cloudfoundry.identity.uaa.authorization.external;

import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authorization.ExternalGroupMappingAuthorizationManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.map.annotate.JsonSerialize.Inclusion;
import org.springframework.util.StringUtils;

public class LdapGroupMappingAuthorizationManager implements ExternalGroupMappingAuthorizationManager {

	private ScimGroupExternalMembershipManager externalMembershipManager;

	private ScimGroupProvisioning scimGroupProvisioning;

	private static final Log logger = LogFactory.getLog(LdapGroupMappingAuthorizationManager.class);

	private static ObjectMapper mapper = new ObjectMapper();

	private static final String EXTERNAL_GROUP_KEY = "externalGroups.";

	{
		mapper.setSerializationConfig(mapper.getSerializationConfig().withSerializationInclusion(Inclusion.NON_NULL));
	}

	@Override
	public Set<String> findScopesFromAuthorities(String authorities) {

		Set<String> authorityList = new LinkedHashSet<String>();

		if(StringUtils.hasLength(authorities)) {
			Map<String, String> incomingExternalGroupMap = null;
			try {
				incomingExternalGroupMap = mapper.readValue(authorities.getBytes(), Map.class);
			}
			catch (Throwable t) {
				logger.error("Unable to read external groups", t);
			}

			if (null != incomingExternalGroupMap) {

				Set<String> externalGroups = new HashSet<String>();
				for (int i = 0; incomingExternalGroupMap.containsKey(EXTERNAL_GROUP_KEY + i); i++) {
					externalGroups.add(incomingExternalGroupMap.get(EXTERNAL_GROUP_KEY + i));
				}

				Set<ScimGroupExternalMember> externalGroupMaps = new LinkedHashSet<ScimGroupExternalMember>();
				for (String externalGroup : externalGroups) {
					// Find UAA groups mapped to external groups
					externalGroupMaps.addAll(externalMembershipManager.getExternalGroupMapsByExternalGroup(externalGroup));
				}

				// Add matching authorities to the token
				for (ScimGroupExternalMember externalGroupMap : externalGroupMaps) {
					ScimGroup scimGroup = scimGroupProvisioning.retrieve(externalGroupMap.getGroupId());
					authorityList.add(scimGroup.getDisplayName());
				}
			}
		}
		return authorityList;
	}

	public void setExternalMembershipManager(ScimGroupExternalMembershipManager externalMembershipManager) {
		this.externalMembershipManager = externalMembershipManager;
	}

	public void setScimGroupProvisioning(ScimGroupProvisioning scimGroupProvisioning) {
		this.scimGroupProvisioning = scimGroupProvisioning;
	}

}
