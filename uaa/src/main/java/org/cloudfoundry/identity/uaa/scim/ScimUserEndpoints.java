package org.cloudfoundry.identity.uaa.scim;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.SpelParseException;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * 
 * @author Luke Taylor
 * @author Dave Syer
 */
@Controller
public class ScimUserEndpoints implements InitializingBean {

	private final Log logger = LogFactory.getLog(getClass());

	private ScimUserProvisioning dao;

	private Collection<String> schemas = Arrays.asList(ScimUser.SCHEMAS);

	@RequestMapping(value = "/User/{userId}", method = RequestMethod.GET)
	@ResponseBody
	public ScimUser getUser(@PathVariable String userId) {
		return dao.retrieveUser(userId);
	}

	@RequestMapping(value = "/User", method = RequestMethod.POST)
	@ResponseStatus(HttpStatus.CREATED)
	@ResponseBody
	public ScimUser createUser(@RequestBody ScimUser user) {
		return dao.createUser(user, generatePassword());
	}

	private static final Random passwordGenerator = new SecureRandom();

	private static String generatePassword() {
		byte[] bytes = new byte[16];
		passwordGenerator.nextBytes(bytes);
		return new String(Hex.encode(bytes));
	}

	@RequestMapping(value = "/User/{userId}", method = RequestMethod.PUT)
	@ResponseBody
	public ScimUser updateUser(@RequestBody ScimUser user, @PathVariable String userId,
			@RequestHeader(value = "If-Match", required = false, defaultValue = "NaN") String etag) {
		if (etag.equals("NaN")) {
			throw new ScimException("Missing If-Match for PUT", HttpStatus.BAD_REQUEST);			
		}
		int version = getVersion(userId, etag);
		user.setVersion(version);
		return dao.updateUser(userId, user);
	}

	@RequestMapping(value = "/User/{userId}", method = RequestMethod.DELETE)
	@ResponseBody
	public ScimUser deleteUser(@PathVariable String userId,
			@RequestHeader(value = "If-Match", required = false, defaultValue = "NaN") String etag) {
		if (etag.equals("NaN")) {
			throw new ScimException("Missing If-Match for DELETE", HttpStatus.BAD_REQUEST);
		}
		int version = getVersion(userId, etag);
		return dao.removeUser(userId, version);
	}

	private int getVersion(String userId, String etag) {
		String value = etag.trim();
		if (value.equals("*")) {
			return dao.retrieveUser(userId).getVersion();
		}
		while (value.startsWith("\"")) {
			value = value.substring(1);
		}
		while (value.endsWith("\"")) {
			value = value.substring(0, value.length()-1);
		}
		try {
			return Integer.valueOf(value);
		} catch (NumberFormatException e) {
			throw new ScimException("Invalid version match header (should be a version number): " + etag, HttpStatus.BAD_REQUEST);
		}
	}

	@RequestMapping(value = "/Users", method = RequestMethod.GET)
	@ResponseBody
	public SearchResults<Map<String, Object>> findUsers(
			@RequestParam(required = false, defaultValue = "id") String attributesCommaSeparated,
			@RequestParam(required = false, defaultValue = "id pr") String filter,
			@RequestParam(required = false, defaultValue = "1") int startIndex,
			@RequestParam(required = false, defaultValue = "100") int count) {

		Collection<ScimUser> input = dao.retrieveUsers(filter);
		String[] attributes = attributesCommaSeparated.split(",");
		Map<String, Expression> expressions = new LinkedHashMap<String, Expression>();

		for (String attribute : attributes) {

			String spel = attribute.replaceAll("emails\\.(.*)", "emails.![$1]");
			logger.debug("Registering SpEL for attribute: " + spel);

			Expression expression;
			try {
				expression = new SpelExpressionParser().parseExpression(spel);
			}
			catch (SpelParseException e) {
				throw new ScimException("Invalid filter expression: [" + filter + "]", HttpStatus.BAD_REQUEST);
			}

			expressions.put(attribute, expression);

		}

		Collection<Map<String, Object>> users = new ArrayList<Map<String, Object>>();
		StandardEvaluationContext context = new StandardEvaluationContext();
		for (ScimUser user : input) {
			Map<String, Object> map = new LinkedHashMap<String, Object>();
			for (String attribute : expressions.keySet()) {
				map.put(attribute, expressions.get(attribute).getValue(context, user));
			}
			users.add(map);
		}

		return new SearchResults<Map<String, Object>>(schemas, users, 1, users.size(), users.size());

	}

	public void setScimUserProvisioning(ScimUserProvisioning dao) {
		this.dao = dao;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(dao, "Dao must be set");
	}
}
