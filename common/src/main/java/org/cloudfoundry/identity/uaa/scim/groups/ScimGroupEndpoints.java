package org.cloudfoundry.identity.uaa.scim.groups;

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
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Controller
public class ScimGroupEndpoints {

	private final ScimGroupProvisioning dao;

	private Map<Class<? extends Exception>, HttpStatus> statuses = new HashMap<Class<? extends Exception>, HttpStatus>();

	private HttpMessageConverter<?>[] messageConverters = new RestTemplate().getMessageConverters().toArray(
																												   new HttpMessageConverter<?>[0]);

	public void setStatuses(Map<Class<? extends Exception>, HttpStatus> statuses) {
		this.statuses = statuses;
	}

	public void setMessageConverters(HttpMessageConverter<?>[] messageConverters) {
		this.messageConverters = messageConverters;
	}

	public ScimGroupEndpoints(ScimGroupProvisioning dao) {
		this.dao = dao;
	}

	@RequestMapping(value = {"/Group", "/Groups"}, method = RequestMethod.GET)
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
		}
		catch (IllegalArgumentException e) {
			throw new ScimException("Invalid filter expression: [" + filter + "]", HttpStatus.BAD_REQUEST);
		}

		AttributeNameMapper mapper = new SimpleAttributeNameMapper(Collections.<String, String> singletonMap("emails\\.(.*)", "emails.![$1]"));
		String[] attributes = attributesCommaSeparated.split(",");
		try {
			return SearchResultsFactory.buildSearchResultFrom(input, startIndex, count, attributes, mapper);
		} catch (SpelParseException e) {
			throw new ScimException("Invalid attributes: [" + attributesCommaSeparated + "]", HttpStatus.BAD_REQUEST);
		} catch (SpelEvaluationException e) {
			throw new ScimException("Invalid attributes: [" + attributesCommaSeparated + "]", HttpStatus.BAD_REQUEST);
		}
	}

	@RequestMapping(value = {"/Group/{groupId}", "/Groups/{groupId}"}, method = RequestMethod.GET)
	@ResponseBody
	public ScimGroup getGroup(@PathVariable String groupId) {
		return dao.retrieveGroup(groupId);
	}

	@RequestMapping(value = {"/Group", "/Groups"}, method = RequestMethod.POST)
	@ResponseStatus(HttpStatus.CREATED)
	@ResponseBody
	public ScimGroup createGroup(@RequestBody ScimGroup group) {
		return dao.createGroup(group);
	}

	@RequestMapping(value = {"/Group/{groupId}", "/Groups/{groupId}"}, method = RequestMethod.PUT)
	@ResponseBody
	public ScimGroup updateGroup(@RequestBody ScimGroup group, @PathVariable String groupId,
								 @RequestHeader(value = "If-Match", required = false) String etag) {
		if (etag == null) {
			throw new ScimException("Missing If-Match for PUT", HttpStatus.BAD_REQUEST);
		}
		int version = getVersion(groupId, etag);
		group.setVersion(version);
		try {
			return dao.updateGroup(groupId, group);
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

	@RequestMapping(value = {"/Group/{groupId}", "/Groups/{groupId}"}, method = RequestMethod.DELETE)
	@ResponseBody
	public ScimGroup deleteGroup(@PathVariable String groupId,
								 @RequestHeader(value = "If-Match", required = false, defaultValue = "*") String etag) {
		return dao.removeGroup(groupId, getVersion(groupId, etag));
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
