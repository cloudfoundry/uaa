package org.cloudfoundry.identity.uaa.scim;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author Luke Taylor
 */
@Controller
public class ScimUserEndpoints implements InitializingBean {
	private final Log logger = LogFactory.getLog(getClass());
	private ScimUserProvisioning dao;
//	private Validator userValidator;
//
//	@Autowired
//	public ScimUserEndpoints(Validator userValidator) {
//		this.userValidator = userValidator;
//	}

	@RequestMapping (value = "/User/{userId}", method= RequestMethod.GET)
	public ResponseEntity<Object> getUser(@PathVariable String userId) {
		try {
			return new ResponseEntity<Object>(dao.retrieveUser(userId), HttpStatus.OK);
		} catch (ScimException e) {
			return new ResponseEntity<Object>(error(e.getMessage()), e.getStatus());
		}
	}

	Map<String,String> error(String message) {
		Map<String,String> errors = new HashMap<String, String>();
		errors.put("error", message);
		return errors;
	}

	@RequestMapping (value = "/User", method= RequestMethod.POST)
	public ResponseEntity<Object> createUser(@RequestBody ScimUser user) {
		try {
			ScimUser newUser = dao.createUser(user);

			return new ResponseEntity<Object>(newUser, HttpStatus.CREATED);
		} catch (ScimException e) {
			return new ResponseEntity<Object>(error(e.getMessage()), e.getStatus());
		}
	}

	@RequestMapping (value = "/User/{userId}", method= RequestMethod.PUT)
	public ResponseEntity<ScimUser> updateUser(@RequestBody ScimUser user, @PathVariable String userId) {
		ScimUser updatedUser = dao.updateUser(userId, user);

		return new ResponseEntity<ScimUser>(updatedUser, HttpStatus.OK);
	}

	public void setDao(ScimUserProvisioning dao) {
		this.dao = dao;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(dao, "Dao must be set");
	}
}
