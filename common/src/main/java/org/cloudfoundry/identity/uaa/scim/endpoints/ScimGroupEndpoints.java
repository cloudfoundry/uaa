package org.cloudfoundry.identity.uaa.scim.endpoints;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.error.ConvertingExceptionView;
import org.cloudfoundry.identity.uaa.error.ExceptionReport;
import org.cloudfoundry.identity.uaa.scim.ScimCore;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidScimResourceException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.expression.spel.SpelEvaluationException;
import org.springframework.expression.spel.SpelParseException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.View;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Controller
public class ScimGroupEndpoints {

	private final ScimGroupProvisioning dao;

	private ScimGroupMembershipManager membershipManager;

	private Map<Class<? extends Exception>, HttpStatus> statuses = new HashMap<Class<? extends Exception>, HttpStatus>();

	private HttpMessageConverter<?>[] messageConverters = new RestTemplate().getMessageConverters().toArray(new HttpMessageConverter<?>[0]);

	private final Log logger = LogFactory.getLog(getClass());

	public void setStatuses(Map<Class<? extends Exception>, HttpStatus> statuses) {
		this.statuses = statuses;
	}

	public void setMessageConverters(HttpMessageConverter<?>[] messageConverters) {
		this.messageConverters = messageConverters;
	}

	public ScimGroupEndpoints(ScimGroupProvisioning scimGroupProvisioning, ScimGroupMembershipManager membershipManager) {
		this.dao = scimGroupProvisioning;
		this.membershipManager = membershipManager;
	}

	@RequestMapping(value = {"/Groups"}, method = RequestMethod.GET)
	@ResponseBody
	public SearchResults<?> listGroups(@RequestParam(value = "attributes", required = false) String attributesCommaSeparated,
									  @RequestParam(required = false, defaultValue = "id pr") String filter,
									  @RequestParam(required = false, defaultValue = "created") String sortBy,
									  @RequestParam(required = false, defaultValue = "ascending") String sortOrder,
									  @RequestParam(required = false, defaultValue = "1") int startIndex,
									  @RequestParam(required = false, defaultValue = "100") int count) {
		List<ScimGroup> input;
		try {
			input = dao.retrieveGroups(filter, sortBy, "ascending".equalsIgnoreCase(sortOrder));
			for (ScimGroup group : input.subList(startIndex - 1, startIndex + count - 1)) {
				group.setMembers(membershipManager.getMembers(group.getId()));
			}
		}
		catch (IllegalArgumentException e) {
			throw new ScimException("Invalid filter expression: [" + filter + "]", HttpStatus.BAD_REQUEST);
		}

		if (!StringUtils.hasLength(attributesCommaSeparated)) {
			return new SearchResults<ScimGroup>(Arrays.asList(ScimGroup.SCHEMAS), input, startIndex, count, input.size());
		}

		String[] attributes = attributesCommaSeparated.split(",");
		try {
			return SearchResultsFactory.buildSearchResultFrom(input, startIndex, count, attributes, Arrays.asList(ScimCore.SCHEMAS));
		} catch (SpelParseException e) {
			throw new ScimException("Invalid attributes: [" + attributesCommaSeparated + "]", HttpStatus.BAD_REQUEST);
		} catch (SpelEvaluationException e) {
			throw new ScimException("Invalid attributes: [" + attributesCommaSeparated + "]", HttpStatus.BAD_REQUEST);
		}
	}

	@RequestMapping(value = {"/Groups/{groupId}"}, method = RequestMethod.GET)
	@ResponseBody
	public ScimGroup getGroup(@PathVariable String groupId) {
		logger.debug("retrieving group with id: " + groupId);
		ScimGroup group = dao.retrieveGroup(groupId);
		group.setMembers(membershipManager.getMembers(groupId));
		return group;
	}

	@RequestMapping(value = {"/Groups"}, method = RequestMethod.POST)
	@ResponseStatus(HttpStatus.CREATED)
	@ResponseBody
	public ScimGroup createGroup(@RequestBody ScimGroup group) {
		ScimGroup created = dao.createGroup(group);
		if (group.getMembers() != null) {
			for (ScimGroupMember member : group.getMembers()) {
				try {
					membershipManager.addMember(created.getId(), member);
				} catch (ScimException ex) {
					logger.warn("Attempt to add invalid member: " + member.getMemberId() + " to group: " + group.getId());
					dao.removeGroup(created.getId(), created.getVersion());
					throw new InvalidScimResourceException("Invalid group member: " + member.getMemberId());
				}
			}
		}
		created.setMembers(membershipManager.getMembers(created.getId()));
		return created;
	}

	@RequestMapping(value = {"/Groups/{groupId}"}, method = RequestMethod.PUT)
	@ResponseBody
	public ScimGroup updateGroup(@RequestBody ScimGroup group, @PathVariable String groupId,
								 @RequestHeader(value = "If-Match", required = false) String etag) {
		if (etag == null) {
			throw new ScimException("Missing If-Match for PUT", HttpStatus.BAD_REQUEST);
		}
		logger.debug("updating group: " + groupId);
		int version = getVersion(groupId, etag);
		group.setVersion(version);

		ScimGroup existing = getGroup(groupId);
		try {
			ScimGroup updated = dao.updateGroup(groupId, group);
			if (group.getMembers() != null) {
				membershipManager.updateOrAddMembers(updated.getId(), group.getMembers());
			}
			updated.setMembers(membershipManager.getMembers(updated.getId()));
			return updated;
		} catch (IncorrectResultSizeDataAccessException ex) {
			logger.error("Error updating group, restoring to previous state");
			// restore to correct state before reporting error
			existing.setVersion(getVersion(groupId, "*"));
			dao.updateGroup(groupId, existing);
			throw new ScimException(ex.getMessage(), ex, HttpStatus.CONFLICT);
		} catch (ScimResourceNotFoundException ex) {
			logger.error("Error updating group, restoring to previous state: " + existing);
			// restore to correct state before reporting error
			existing.setVersion(getVersion(groupId, "*"));
			dao.updateGroup(groupId, existing);
			throw new ScimException(ex.getMessage(), ex, HttpStatus.BAD_REQUEST);
		}
	}

	/*
			SCIM spec lists the PATCH operaton as optional, so leaving it un-implemented for now while we wait for
			https://jira.springsource.org/browse/SPR-7985 which adds support for RequestMethod.PATCH in version '3.2 M2'
		*/
	/*
		@RequestMapping(value = { "/Group/{groupId}", "/Groups/{groupId}" }, method = RequestMethod.PATCH)
		@ResponseBody
		public ScimGroup updateGroup(@RequestBody ScimGroup group, @PathVariable String groupId,
									 @RequestHeader(value = "If-Match", required = false) String etag) {

		}
		*/

	@RequestMapping(value = {"/Groups/{groupId}"}, method = RequestMethod.DELETE)
	@ResponseBody
	public ScimGroup deleteGroup(@PathVariable String groupId,
								 @RequestHeader(value = "If-Match", required = false, defaultValue = "*") String etag) {
		ScimGroup group = getGroup(groupId);
		logger.debug("deleting group: " + group);
		try {
			membershipManager.removeMembersByGroupId(groupId);
			membershipManager.removeMembersByMemberId(groupId);
			dao.removeGroup(groupId, getVersion(groupId, etag));
		} catch (IncorrectResultSizeDataAccessException ex) {
			logger.error("error deleting group, restoring system to previous state");
			throw new ScimException("error deleting group: " + groupId, ex, HttpStatus.CONFLICT);
		}
		return group;
	}

	@ExceptionHandler
	public View handleException(Exception t, HttpServletRequest request) throws ScimException {
		ScimException e = new ScimException("Unexpected error", t, HttpStatus.INTERNAL_SERVER_ERROR);
		if (t instanceof ScimException) {
			e = (ScimException) t;
		} else if (t instanceof DataIntegrityViolationException) {
			e = new ScimException(t.getMessage(), t, HttpStatus.BAD_REQUEST);
		} else {
			Class<?> clazz = t.getClass();
			for (Class<?> key : statuses.keySet()) {
				if (key.isAssignableFrom(clazz)) {
					e = new ScimException(t.getMessage(), t, statuses.get(key));
					break;
				}
			}
		}
		// User can supply trace=true or just trace (unspecified) to get stack traces
		boolean trace = request.getParameter("trace") != null && !request.getParameter("trace").equals("false");
		return new ConvertingExceptionView(new ResponseEntity<ExceptionReport>(new ExceptionReport(e, trace),
																					  e.getStatus()), messageConverters);
	}

	private int getVersion(String groupId, String etag) {
		String value = etag.trim();
		while (value.startsWith("\"")) {
			value = value.substring(1);
		}
		while (value.endsWith("\"")) {
			value = value.substring(0, value.length() - 1);
		}
		if (value.equals("*")) {
			return dao.retrieveGroup(groupId).getVersion();
		}
		try {
			return Integer.valueOf(value);
		} catch (NumberFormatException e) {
			throw new ScimException("Invalid version match header (should be a version number): " + etag,
										   HttpStatus.BAD_REQUEST);
		}
	}
}
