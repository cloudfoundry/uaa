package org.cloudfoundry.identity.uaa.scim.groups;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.error.ConvertingExceptionView;
import org.cloudfoundry.identity.uaa.error.ExceptionReport;
import org.cloudfoundry.identity.uaa.scim.*;
import org.cloudfoundry.identity.uaa.security.DefaultSecurityContextAccessor;
import org.cloudfoundry.identity.uaa.security.SecurityContextAccessor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.expression.spel.SpelEvaluationException;
import org.springframework.expression.spel.SpelParseException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.View;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Controller
public class ScimGroupEndpoints {

	private final ScimGroupProvisioning dao;

	private ScimGroupMembershipManager membershipManager;

	private SecurityContextAccessor context = new DefaultSecurityContextAccessor();

	private Map<Class<? extends Exception>, HttpStatus> statuses = new HashMap<Class<? extends Exception>, HttpStatus>();

	private HttpMessageConverter<?>[] messageConverters = new RestTemplate().getMessageConverters().toArray(new HttpMessageConverter<?>[0]);

	private final Log logger = LogFactory.getLog(getClass());

	public void setContext(SecurityContextAccessor context) {
		this.context = context;
	}

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
	public SearchResults<Map<String, Object>> listGroups(@RequestParam(value = "attributes", required = false, defaultValue = "id") String attributesCommaSeparated,
									  @RequestParam(required = false, defaultValue = "id pr") String filter,
									  @RequestParam(required = false, defaultValue = "created") String sortBy,
									  @RequestParam(required = false, defaultValue = "ascending") String sortOrder,
									  @RequestParam(required = false, defaultValue = "1") int startIndex,
									  @RequestParam(required = false, defaultValue = "100") int count) {
		List<ScimGroup> input;
		try {
			input = dao.retrieveGroups(filter, sortBy, "ascending".equalsIgnoreCase(sortOrder));
			for (ScimGroup group : input) {
				group.setMembers(membershipManager.getMembers(group.getId()));
			}
		}
		catch (IllegalArgumentException e) {
			throw new ScimException("Invalid filter expression: [" + filter + "]", HttpStatus.BAD_REQUEST);
		}

		String[] attributes = attributesCommaSeparated.split(",");
		try {
			return SearchResultsFactory.buildSearchResultFrom(input, startIndex, count, attributes);
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
					throw new ScimException("Invalid group member: " + member.getMemberId(), HttpStatus.BAD_REQUEST);
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
		checkIfUpdateAllowed(groupId);
		logger.debug("updating group: " + groupId);
		int version = getVersion(groupId, etag);
		group.setVersion(version);
		try {
			ScimGroup updated = dao.updateGroup(groupId, group);
			if (group.getMembers() != null) {
				membershipManager.updateOrAddMembers(updated.getId(), group.getMembers());
			}
			updated.setMembers(membershipManager.getMembers(updated.getId()));
			return updated;
		} catch (IncorrectResultSizeDataAccessException e) {
			throw new ScimException(e.getMessage(), HttpStatus.CONFLICT);
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
		dao.removeGroup(groupId, getVersion(groupId, etag));
		membershipManager.removeMembersByGroupId(groupId);
		membershipManager.removeMembersByMemberId(groupId);
		return group;
	}

	protected void checkIfUpdateAllowed(String groupId) {
		if (context.isAdmin()) {
			return;
		}
		if (context.isUser()) {
			if (membershipManager.getAdminMembers(groupId).contains(new ScimGroupMember(context.getUserId()))) {
				return;
			} else
				throw new ScimException(context.getUserId() + " does not have privileges to update group: " + groupId, HttpStatus.UNAUTHORIZED);
		}
		throw new ScimException("Only group members with required privileges can update group", HttpStatus.UNAUTHORIZED);
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
		if (value.equals("*")) {
			return dao.retrieveGroup(groupId).getVersion();
		}
		while (value.startsWith("\"")) {
			value = value.substring(1);
		}
		while (value.endsWith("\"")) {
			value = value.substring(0, value.length() - 1);
		}
		try {
			return Integer.valueOf(value);
		} catch (NumberFormatException e) {
			throw new ScimException("Invalid version match header (should be a version number): " + etag,
										   HttpStatus.BAD_REQUEST);
		}
	}
}
