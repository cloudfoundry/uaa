package org.cloudfoundry.identity.uaa.scim;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.ExceptionHandler;
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

	// private Validator userValidator;
	//
	// @Autowired
	// public ScimUserEndpoints(Validator userValidator) {
	// this.userValidator = userValidator;
	// }

	@RequestMapping(value = "/User/{userId}", method = RequestMethod.GET)
	public ResponseEntity<Object> getUser(@PathVariable String userId) {
		return new ResponseEntity<Object>(dao.retrieveUser(userId), HttpStatus.OK);
	}

	Map<String, String> error(String message) {
		Map<String, String> errors = new HashMap<String, String>();
		errors.put("error", message);
		return errors;
	}

	@RequestMapping(value = "/User", method = RequestMethod.POST)
	public ResponseEntity<Object> createUser(@RequestBody ScimUser user) {
		ScimUser newUser = dao.createUser(user);
		return new ResponseEntity<Object>(newUser, HttpStatus.CREATED);
	}

	@RequestMapping(value = "/User/{userId}", method = RequestMethod.PUT)
	public ResponseEntity<ScimUser> updateUser(@RequestBody ScimUser user, @PathVariable String userId) {
		ScimUser updatedUser = dao.updateUser(userId, user);
		return new ResponseEntity<ScimUser>(updatedUser, HttpStatus.OK);
	}

	@RequestMapping(value = "/User/{userId}", method = RequestMethod.DELETE)
	public ResponseEntity<ScimUser> deleteUser(@PathVariable String userId) {
		ScimUser updatedUser = dao.removeUser(userId);
		return new ResponseEntity<ScimUser>(updatedUser, HttpStatus.OK);
	}

	@ExceptionHandler
	@ResponseBody
	@ResponseStatus(HttpStatus.CONFLICT)
	public Map<String, String> handleIllegalArggument(IllegalArgumentException e) {
		Map<String, String> map = new HashMap<String, String>();
		map.put("error", "illegal_argument");
		map.put("message", e.getMessage());
		StringWriter trace = new StringWriter();
		e.printStackTrace(new PrintWriter(trace));
		map.put("trace", trace.toString());
		return map;
	}

	@ExceptionHandler
	public ResponseEntity<Map<String, String>> handleScimException(ScimException e, HttpServletResponse response) throws IOException {
		Map<String, String> map = new HashMap<String, String>();
		map.put("error", "scim_exception");
		map.put("message", e.getMessage());
		StringWriter trace = new StringWriter();
		e.printStackTrace(new PrintWriter(trace));
		map.put("trace", trace.toString());
		return new ResponseEntity<Map<String,String>>(map, e.getStatus());
	}

	public void setDao(ScimUserProvisioning dao) {
		this.dao = dao;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(dao, "Dao must be set");
	}
}
