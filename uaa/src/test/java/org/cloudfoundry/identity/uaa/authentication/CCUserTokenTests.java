package org.cloudfoundry.identity.uaa.authentication;

import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SignatureException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyFixnum;
import org.jruby.RubyString;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.runtime.marshal.MarshalStream;
import org.jruby.runtime.marshal.UnmarshalStream;
import org.jruby.util.ByteList;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.codec.Utf8;
import org.springframework.util.Assert;

public class CCUserTokenTests {
	SecretKey macKey;
	// Token generated from ruby script.
	// @user_name="joe", @valid_until=10001323447076
	// Hmac:
	// 00000000  a2 00 22 1c 1b 56 85 c7 fa 8d 99 95 72 0f 2c 8c  |.."..V......r.,.|
	// 00000010  4d 85 82 2f                                      |M../|

	static final String TOKEN = "04085b084922086a6f65063a0645466c2b0824d3549d18092219a200221c1b5685c7fa8d9995720f2c8c4d85822f";

	@Before
	public void setUp() throws Exception {
		macKey = new SecretKeySpec("5".getBytes("UTF-8"), "HMACSHA1");
	}

	@Test
	public void sigHasExpectedValue() throws Exception {
		UserToken ut = new UserToken("joe", 10001323447076L, macKey);
		assertEquals("a200221c1b5685c7fa8d9995720f2c8c4d85822f", new String(Hex.encode(ut.signature)));
	}

	@Test
	public void rubyGeneratedTokenDecodesOk() throws Exception {
		UserToken ut = UserToken.decode(TOKEN, macKey);
		assertEquals("joe", ut.getUsername());
		assertEquals(10001323447076L, ut.getValidUntil());
		assertEquals("a200221c1b5685c7fa8d9995720f2c8c4d85822f", new String(Hex.encode(ut.signature)));
	}

	@Test
	public void tokenEncodesToCorrectValue() throws Exception {
		UserToken ut = new UserToken("joe", 10001323447076L, macKey);

		String token = ut.encode();

		// Check we can decode to the same token
		UserToken decoded = UserToken.decode(token, macKey);
		assertEquals(ut, decoded);

		assertEquals("04085b0822086a6f656c2b0824d3549d18092219a200221c1b5685c7fa8d9995720f2c8c4d85822f", ut.encode());
	}
}

/**
 * PoC of implementation of the CC UserToken in Java
 *
 * @author Luke Taylor
 */
class UserToken {
	final String username;
	final long validUntil;
	final byte[] signature;

	public UserToken(String username, byte[] key) {
		this(username, 9999999999999L, key);
	}

	public UserToken(String username, long tokenLifetime, byte[] key) {
		this(username, System.currentTimeMillis() + tokenLifetime, new SecretKeySpec(key, "HMACSHA1"));
	}

	UserToken(String username, long validUntil, SecretKey key) {
		this.username = username;
		this.validUntil = validUntil;
		this.signature = sign(username, validUntil, key);
	}

	public String encode() {
		RubyString name = RubyString.newString(Ruby.getGlobalRuntime(), Utf8.encode(username));
		RubyFixnum valid = RubyFixnum.newFixnum(Ruby.getGlobalRuntime(), validUntil);
		RubyString sig = RubyString.newString(Ruby.getGlobalRuntime(), signature);

		RubyArray array = RubyArray.newArrayLight(Ruby.getGlobalRuntime(), name, valid, sig);

		ByteArrayOutputStream baos = new ByteArrayOutputStream();

		try {
			MarshalStream ms = new MarshalStream(Ruby.getGlobalRuntime(), baos, -1);
			ms.dumpObject(array);
		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}

		byte[] bytes = baos.toByteArray();

//		HexDumpEncoder enc = new HexDumpEncoder();
//		System.out.println("Marshalled bytes: \n" + enc.encode(bytes));

		return new String(Hex.encode(bytes));
	}

	/**
	 *
	 * @param token the token string containing the ruby-marshalled username, expiry time and HMAC signature
	 * @param key Used to validate the signature of the token.
	 *
	 * @return a UserToken instance containing the data
	 * @throws SignatureException if the signature in the token string does not match the one calculated using the
	 *        supplied key.
	 */
	public static UserToken decode(String token, SecretKey key) throws SignatureException {
		ByteArrayInputStream bytes = new ByteArrayInputStream(Hex.decode(token));

		try {
			UnmarshalStream stream  = new UnmarshalStream(Ruby.getGlobalRuntime(), bytes, null, false);
			IRubyObject object = stream.unmarshalObject();

			Assert.isInstanceOf(RubyArray.class, object);

			RubyArray array = (RubyArray) object;

			Assert.isTrue(array.size() == 3);

			String username = (String) array.get(0);
			Long validUntil = (Long) array.get(1);
			ByteList sigBytes = ((RubyString)array.eltOk(2)).getByteList();

//			HexDumpEncoder enc = new HexDumpEncoder();
//			System.out.println("Signature from token is: \n" + enc.encode(sigBytes.unsafeBytes()));

			UserToken ut = new UserToken(username, validUntil, key);

			if (!Arrays.equals(ut.signature, sigBytes.unsafeBytes())) {
				throw new SignatureException("Signature is invalid for username = " + username + ", validUntil " + validUntil);
			}

			return ut;
		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}

	}

	public String getUsername() {
		return username;
	}

	public long getValidUntil() {
		return validUntil;
	}

	private static byte[] sign(String username, long validUntil, SecretKey key) {
		Mac mac;
		try {
			mac = Mac.getInstance("HMACSHA1");
			mac.init(key);
		}
		catch (GeneralSecurityException e) {
			throw new RuntimeException("Failed to create and initialize MAC: ", e);
		}

		byte[] bytesToSign = Utf8.encode(username + validUntil);
//		HexDumpEncoder enc = new HexDumpEncoder();
//		System.out.println("Signing bytes: \n" + enc.encode(bytesToSign));
		byte[] sig = mac.doFinal(bytesToSign);
//		System.out.println("Signature is: \n" + enc.encode(sig));
		return sig;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}

		UserToken userToken = (UserToken) o;

		if (!Arrays.equals(signature, userToken.signature)) {
			return false;
		}

		return true;
	}

	@Override
	public int hashCode() {
		return signature != null ? Arrays.hashCode(signature) : 0;
	}
}
