package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.util.Assert;

import java.security.SecureRandom;
import java.util.List;
import java.util.Random;

/**
 * User data for authentication against UAA's internal authentication provider.
 *
 * @author Luke Taylor
 * @author Dave Syer
 */
public class UaaUser {
	private final String id;

	private final String username;

	private final String password;

	private final String email;

	private List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_USER");

	UaaUser(String username, String password) {
		this(username, password, null);
	}

	UaaUser(String username, String password, String email) {
		this("NaN", username, password, email);
	}

	UaaUser(String id, String username, String password, String email) {
		Assert.hasText(username, "Username cannot be empty");
		Assert.hasText(id, "Id cannot be null");
		Assert.hasText(email, "Email is required");
		this.id = id;
		this.username = username;
		this.password = password;
		// TODO: Canonicalize email?
		this.email = email;
	}

	/**
	 * Create a new user from Scim data.
	 */
	UaaUser(ScimUser scim) {
		// TODO: Will password be passed in SCIM request or what?
		this(scim.getUserName(), generatePassword(), scim.getPrimaryEmail().getValue());
	}

	private static final Random passwordGenerator = new SecureRandom();

	private static String generatePassword() {
		byte[] bytes = new byte[16];
		passwordGenerator.nextBytes(bytes);
		return new String(Hex.encode(bytes));
	}

	public String getId() {
		return id;
	}

	public String getUsername() {
		return username;
	}

	public String getPassword() {
		return password;
	}

	public String getEmail() {
		return email;
	}

	public List<GrantedAuthority> getAuthorities() {
		return authorities;
	}

	public UaaUser id(int id) {
		if ("Nan".equals(this.id)) {
			throw new IllegalStateException("Id already set");
		}
		return new UaaUser(Integer.toString(id), username, password, email);
	}

	/**
	 * Convert to SCIM data for use in JSON responses.
	 */
	ScimUser scimUser() {
		ScimUser scim = new ScimUser(getId());
		scim.addEmail(getEmail());
		scim.setUserName(getUsername());
		return scim;
	}
}
