package org.cloudfoundry.identity.uaa.scim;

import org.junit.Test;

/**
 * @author Luke Taylor
 */
public class DefaultPasswordValidatorTests {
	DefaultPasswordValidator v = new DefaultPasswordValidator();

	private ScimUser roz = new ScimUser("1234", "roz", "Roslyn", "MacRae");

	public DefaultPasswordValidatorTests() {
		roz.setNickName("Rose");
		roz.addEmail("rm@here.com");
	}

	@Test(expected = InvalidPasswordException.class)
	public void passwordIsNotAllowedInPassword() throws Exception {
		v.validate("pA@ssword0!!", roz);
	}

	@Test
	public void minimumLengthPasswordIsAccepted() {
		v.validate("im10chars!!", roz);
	}

	@Test(expected = InvalidPasswordException.class)
	public void tooShortPasswordIsRejected() {
		v.validate("toosh0rt!", roz);
	}

	@Test(expected = InvalidPasswordException.class)
	public void digitIsRequired() {
		v.validate("Idon'thaveanynumbers", roz);
	}

	@Test(expected = InvalidPasswordException.class)
	public void numberSequenceIsRejected() {
		v.validate("okApartfrom3456789", roz);
	}

	@Test(expected = InvalidPasswordException.class)
	public void qwertySequenceIsRejected() {
		v.validate("0kApartfromFGHJKL", roz);
	}

	@Test(expected = InvalidPasswordException.class)
	public void repeatedCharSequenceIsRejected() throws Exception {
		v.validate("0Ujyafffff", roz);
	}

	@Test(expected = InvalidPasswordException.class)
	public void usernameisNotAllowed() throws Exception {
		v.validate("HiTh3reI'mRozita", roz);
	}

	@Test(expected = InvalidPasswordException.class)
	public void usernameisNotAllowedInReverse() throws Exception {
		v.validate("HiTh3reI'mZoRro", roz);
	}

	@Test(expected = InvalidPasswordException.class)
	public void givenNameIsNotAllowed() throws Exception {
		v.validate("HiTh3reI'mrOslynSoIam", roz);
	}

	@Test(expected = InvalidPasswordException.class)
	public void familyNameIsNotAllowed() throws Exception {
		v.validate("HiTh3reMyNameIsmacRae", roz);
	}

	@Test(expected = InvalidPasswordException.class)
	public void emailIsNotAllowed() throws Exception {
		v.validate("HiTh3reI'mrm@Here.Com", roz);
	}
}
