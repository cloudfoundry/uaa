package org.cloudfoundry.identity.uaa.authorization.external;

import java.io.IOException;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import org.cloudfoundry.identity.uaa.authorization.ExternalAuthorizationManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.codehaus.jackson.JsonParseException;
import org.codehaus.jackson.map.JsonMappingException;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.map.annotate.JsonSerialize.Inclusion;
import org.springframework.util.StringUtils;

public class LdapGroupMappingAuthorizationManager implements ExternalAuthorizationManager {

	private ScimGroupExternalMembershipManager externalMembershipManager;

	private ScimGroupProvisioning scimGroupProvisioning;

	private static ObjectMapper mapper = new ObjectMapper();

	{
		mapper.setSerializationConfig(mapper.getSerializationConfig().withSerializationInclusion(Inclusion.NON_NULL));
	}

	@Override
	public Set<String> findScopesFromAuthorities(String authorities) {

		Set<String> authorityList = new LinkedHashSet<String>();

		if(StringUtils.hasLength(authorities)) {
			@SuppressWarnings("unchecked")
			Map<String, String> incomingExternalGroupMap = null;
			try {
				incomingExternalGroupMap = mapper.readValue(authorities.getBytes(), Map.class);
			}
			catch (JsonParseException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			catch (JsonMappingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			String externalGroupKey = "externalGroups.";

			if (null != incomingExternalGroupMap) {

				Set<String> externalGroups = new HashSet<String>();
				for (int i = 0; incomingExternalGroupMap.containsKey(externalGroupKey + i); i++) {
					externalGroups.add(incomingExternalGroupMap.get(externalGroupKey + i));
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
