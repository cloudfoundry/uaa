package org.cloudfoundry.identity.uaa.scim;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.SpelParseException;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.http.HttpStatus;
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

	private final Map<String, UaaUser> users;

	public InMemoryScimUserProvisioning(Map<String, UaaUser> users) {
		this.users = users;
	}

	private UaaUser addUser(UaaUser user) {
		users.put(user.getUsername(), user.id(counter++));
		return users.get(user.getUsername());
	}

	/**
	 * Convert to SCIM data for use in JSON responses.
	 */
	private ScimUser scimUser(UaaUser user) {
		ScimUser scim = new ScimUser(user.getId(), user.getUsername(), user.getGivenName(), user.getFamilyName());
		scim.addEmail(user.getEmail());
		return scim;
	}

	private UaaUser getUaaUser(ScimUser scim, String password) {
		return new UaaUser(scim.getUserName(), password, scim.getPrimaryEmail(), scim.getGivenName(), scim.getFamilyName());
	}

	@Override
	public ScimUser retrieveUser(String id) {
		for (UaaUser user : users.values()) {
			if (user.getId().equals(id)) {
				return scimUser(user);
			}
		}
		throw new ScimException("User " + id + " does not exist", HttpStatus.NOT_FOUND);
	}

	@Override
	public Collection<ScimUser> retrieveUsers() {
		Collection<ScimUser> result = new ArrayList<ScimUser>();
		for (UaaUser user : users.values()) {
			result.add(scimUser(user));
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
			throw new ScimException("Invalid filter expression: [" + filter + "]", HttpStatus.BAD_REQUEST);
		}

		for (ScimUser user : retrieveUsers()) {
			if (expression.getValue(context, user, Boolean.class)) {
				users.add(user);
			}
		}

		return users;

	}

	@Override
	public ScimUser removeUser(String id) {
		UaaUser removed = users.remove(id);
		if (removed == null) {
			throw new ScimException("User " + id + " does not exist", HttpStatus.NOT_FOUND);
		}
		return scimUser(removed);
	}

	@Override
	public ScimUser createUser(ScimUser scim, String password) {
		Assert.isTrue(!users.containsKey(scim.getUserName()), "A user with name '" + scim.getUserName()
				+ "' already exists");
		Assert.notEmpty(scim.getEmails(), "At least one email is required");

		try {
			UaaUser user = addUser(getUaaUser(scim, password));

			return scimUser(user);
		}
		catch (IllegalArgumentException e) {
			throw new ScimException(e.getMessage(), HttpStatus.BAD_REQUEST);
		}
	}

	@Override
	public ScimUser updateUser(String id, ScimUser user) {
		return null;
	}
}
