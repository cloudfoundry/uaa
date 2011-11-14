package org.cloudfoundry.identity.uaa.scim;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.BeanWrapper;
import org.springframework.beans.BeanWrapperImpl;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.SpelParseException;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
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
		return dao.createUser(user);
	}

	@RequestMapping(value = "/User/{userId}", method = RequestMethod.PUT)
	@ResponseBody
	public ScimUser updateUser(@RequestBody ScimUser user, @PathVariable String userId) {
		return dao.updateUser(userId, user);
	}

	@RequestMapping(value = "/User/{userId}", method = RequestMethod.DELETE)
	@ResponseBody
	public ScimUser deleteUser(@PathVariable String userId) {
		return dao.removeUser(userId);
	}

	@RequestMapping(value = "/Users/{filter}", method = RequestMethod.GET)
	@ResponseBody
	public SearchResults<Map<String, Object>> findUsers(@PathVariable String attributesCommaSeparated,
			@PathVariable String filter, @RequestParam(required = false, defaultValue = "1") int startIndex,
			@RequestParam(required = false, defaultValue = "100") int count) {

		Collection<ScimUser> input = dao.retrieveUsers();
		Collection<Map<String, Object>> users = new ArrayList<Map<String, Object>>();

		String spel = filter.replace(" eq ", " == ").replace(" pr", "!=null").replace(" ge ", " >= ")
				.replace(" le ", " <= ").replace(" gt ", " > ").replace(" lt ", " < ")
				.replaceAll(" co '(.*?)'", ".contains('$1')").replaceAll(" sw '(.*?)'", ".startsWith('$1')");

		logger.debug("Filtering users with SpEL: " + spel);

		StandardEvaluationContext context = new StandardEvaluationContext();
		Expression expression;
		try {
			expression = new SpelExpressionParser().parseExpression(spel);
		}
		catch (SpelParseException e) {
			throw new ScimException("Invalid filter expression: [" + filter + "]", HttpStatus.BAD_REQUEST);
		}

		String[] attributes = attributesCommaSeparated.split(",");

		for (ScimUser user : input) {
			if (expression.getValue(context, user, Boolean.class)) {
				Map<String, Object> map = new LinkedHashMap<String, Object>();
				BeanWrapper wrapper = new BeanWrapperImpl(user);
				for (String attribute : attributes) {
					map.put(attribute, wrapper.getPropertyValue(attribute));
				}
				users.add(map);
			}
		}

		return new SearchResults<Map<String, Object>>(schemas, users, 1, users.size(), users.size());

	}

	public void setDao(ScimUserProvisioning dao) {
		this.dao = dao;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(dao, "Dao must be set");
	}
}
