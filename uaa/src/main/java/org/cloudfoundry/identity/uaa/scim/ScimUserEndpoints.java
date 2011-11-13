package org.cloudfoundry.identity.uaa.scim;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
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

	public void setDao(ScimUserProvisioning dao) {
		this.dao = dao;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(dao, "Dao must be set");
	}
}
