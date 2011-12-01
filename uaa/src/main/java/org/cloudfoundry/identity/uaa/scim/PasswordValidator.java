package org.cloudfoundry.identity.uaa.scim;

/**
 * Validates password values when creating users or changing passwords.
 *
 * Should implement the password policy defined for the system.
 * User interfaces should obviously also implement the same policy.
 *
 * @author Luke Taylor
 */
public interface PasswordValidator {
	/**
	 * Validates the password as to whether it is valid for a specific user.
	 *
	 * @param password the trial password
	 * @param user the user data to whom the password applies
	 */
	void validate(String password, ScimUser user) throws InvalidPasswordException;
}
