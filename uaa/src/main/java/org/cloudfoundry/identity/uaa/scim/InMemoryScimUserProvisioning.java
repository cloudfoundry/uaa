package org.cloudfoundry.identity.uaa.scim;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.SpelParseException;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.util.Assert;

/**
 * In-memory user account information storage.
 * 
 * @author Luke Taylor
 * @author Dave Syer
 */
public class InMemoryScimUserProvisioning implements ScimUserProvisioning {

	private final Log logger = LogFactory.getLog(getClass());

	private int counter = 1;

	private final ConcurrentMap<String, UaaUser> users = new ConcurrentHashMap<String, UaaUser>();

	private final ConcurrentMap<String, String> ids = new ConcurrentHashMap<String, String>();

	public InMemoryScimUserProvisioning(Map<String, UaaUser> users) {
		for (UaaUser user : users.values()) {
			addUser(user);
		}
	}

	private UaaUser addUser(UaaUser user) {
		if (user.getId().equals("NaN")) {
			user = user.id(counter++);
		}
		users.put(user.getUsername(), user);
		ids.put(user.getId(), user.getUsername());
		return users.get(user.getUsername());
	}

	/**
	 * Convert to SCIM data for use in JSON responses.
	 */
	private ScimUser getScimUser(UaaUser user) {
		ScimUser scim = new ScimUser(user.getId(), user.getUsername(), user.getGivenName(), user.getFamilyName());
		scim.addEmail(user.getEmail());
		return scim;
	}

	private UaaUser getUaaUser(ScimUser scim, String password) {
		return new UaaUser(scim.getUserName(), password, scim.getPrimaryEmail(), scim.getGivenName(),
				scim.getFamilyName());
	}

	@Override
	public ScimUser retrieveUser(String id) throws UserNotFoundException {
		if (!ids.containsKey(id)) {
			throw new UserNotFoundException("User " + id + " does not exist");
		}
		return getScimUser(users.get(ids.get(id)));
	}

	@Override
	public Collection<ScimUser> retrieveUsers() {
		Collection<ScimUser> result = new ArrayList<ScimUser>();
		for (UaaUser user : users.values()) {
			result.add(getScimUser(user));
		}
		return result;
	}

	@Override
	public Collection<ScimUser> retrieveUsers(String filter) {

		Collection<ScimUser> users = new ArrayList<ScimUser>();

		String spel = filter.replace(" eq ", " == ").replace(" pr", "!=null").replace(" ge ", " >= ")
				.replace(" le ", " <= ").replace(" gt ", " > ").replace(" lt ", " < ")
				.replaceAll(" co '(.*?)'", ".contains('$1')").replaceAll(" sw '(.*?)'", ".startsWith('$1')")
				.replaceAll("emails\\.(.*?)\\.(.*?)\\((.*?)\\)", "emails.^[$1.$2($3)]!=null");

		logger.debug("Filtering users with SpEL: " + spel);

		StandardEvaluationContext context = new StandardEvaluationContext();
		Expression expression;
		try {
			expression = new SpelExpressionParser().parseExpression(spel);
		}
		catch (SpelParseException e) {
			throw new IllegalArgumentException("Invalid filter expression: [" + filter + "]");
		}

		for (ScimUser user : retrieveUsers()) {
			if (expression.getValue(context, user, Boolean.class)) {
				users.add(user);
			}
		}

		return users;

	}

	@Override
	public ScimUser removeUser(String id, int version) throws UserNotFoundException {
		String name = ids.remove(id);
		if (name == null) {
			throw new UserNotFoundException("User " + id + " does not exist");
		}
		UaaUser removed = users.remove(name);
		return getScimUser(removed);
	}

	@Override
	public ScimUser createUser(ScimUser scim, String password) {
		Assert.isTrue(!users.containsKey(scim.getUserName()), "A user with name '" + scim.getUserName()
				+ "' already exists");
		Assert.notEmpty(scim.getEmails(), "At least one email is required");

		UaaUser user = addUser(getUaaUser(scim, password));
		return getScimUser(user);
	}

	@Override
	public ScimUser updateUser(String id, ScimUser user) throws UserNotFoundException {
		if (!ids.containsKey(id)) {
			throw new UserNotFoundException("User " + id + " does not exist");
		}
		UaaUser uaa = users.get(ids.get(id));
		String name = uaa.getUsername();
		users.put(name, getUaaUser(user, uaa.getPassword()).id(Integer.valueOf(id)));
		ids.replace(id, name);
		return user;
	}
}
