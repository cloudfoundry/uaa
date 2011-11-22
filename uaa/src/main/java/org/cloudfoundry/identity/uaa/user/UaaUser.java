package org.cloudfoundry.identity.uaa.user;

import java.util.Date;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.util.Assert;

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
	private final String givenName;
	private final String familyName;
	private final Date created;
	private final Date modified;

	private List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_USER");

	public UaaUser(String username, String password, String email, String givenName, String familyName) {
		this("NaN", username, password, email, givenName, familyName, new Date(), new Date());
	}

	UaaUser(String id, String username, String password, String email, String givenName, String familyName, Date created, Date modified) {
		Assert.hasText(username, "Username cannot be empty");
		Assert.hasText(id, "Id cannot be null");
		Assert.hasText(email, "Email is required");
		Assert.hasText(givenName, "givenName is required");
		Assert.hasText(familyName, "familyName is required");
		this.id = id;
		this.username = username;
		this.password = password;
		// TODO: Canonicalize email?
		this.email = email;
		this.familyName = familyName;
		this.givenName = givenName;
		this.created = created;
		this.modified = modified;
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

	public String getGivenName() {
		return givenName;
	}

	public String getFamilyName() {
		return familyName;
	}

	public List<GrantedAuthority> getAuthorities() {
		return authorities;
	}

	public UaaUser id(int id) {
		if (!"NaN".equals(this.id)) {
			throw new IllegalStateException("Id already set");
		}
		return new UaaUser(Integer.toString(id), username, password, email, givenName, familyName, created, modified);
	}

}
