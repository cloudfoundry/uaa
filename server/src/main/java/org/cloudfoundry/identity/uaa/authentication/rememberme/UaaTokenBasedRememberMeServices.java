package org.cloudfoundry.identity.uaa.authentication.rememberme;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cloudfoundry.identity.uaa.account.UaaUserDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices;
import org.springframework.security.web.authentication.rememberme.InvalidCookieException;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationException;

/**
 * Custom implementation allowing to set a RME cookie which contains 3 items : the encrypted user id, the expiry time and a hashed token.
 * The hashed token contains the user iid, the expiry time, the user agent and the key spring-security component.
 *  
 * @author Stephane CIZERON
 */
public class UaaTokenBasedRememberMeServices extends AbstractRememberMeServices {

	// ~ Static fields/initializers
	// =====================================================================================
	private static final String UTF_8_CHARSET = "UTF-8";

	private static final String SECRET_KEY_SPEC_ALGORITHM = "AES";
	
	private static final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS5Padding";

	private static final String MESSAGE_DIGEST_ALGORITHM = "SHA-256";

	private static final String USER_AGENT_HEADER_NAME = "User-Agent";

	private static final int COOKIE_TOKENS = 3;
	
	// ~ Instance fields
	// ================================================================================================	
	private UaaUserDatabase uaaUserDatabase;
	
	private SecretKeySpec secret;
	
	private IvParameterSpec ivParameterSpec;
	
	/**
	 * 
	 * @param key
	 * @param aesKey
	 * @param uaaUserDatabase
	 */
	protected UaaTokenBasedRememberMeServices(String key,  String aesKey, String aesIv, UaaUserDatabase uaaUserDatabase) {
		// an userDetailsService instance is expected by AbstractRememberMeServices and must be not null but we don't use it
		super(key, new UserDetailsService() {
			@Override
			public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
				return null;
			}
		});
		
		logger.debug("Init " + getClass().getName() + " with aesKey: " + aesKey + " and aesIv: " + aesIv);
		
		this.uaaUserDatabase = uaaUserDatabase;
		this.secret = new SecretKeySpec(Hex.decode(aesKey), SECRET_KEY_SPEC_ALGORITHM);
		this.ivParameterSpec = new IvParameterSpec(Hex.decode(aesIv));
	}

	@Override
	protected void onLoginSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication successfulAuthentication) {
		UaaPrincipal uaaPrincipal = (UaaPrincipal) successfulAuthentication.getPrincipal();
		UaaUser uaaUser = this.uaaUserDatabase.retrieveUserById(uaaPrincipal.getId());
		long expiryTime = System.currentTimeMillis() + 1000L * getTokenValiditySeconds();
		String signatureValue = makeTokenSignature(uaaUser.getId(), expiryTime, uaaUser.getModified(), request.getHeader(USER_AGENT_HEADER_NAME));
		try {
			setCookie(new String[] { encrypt(uaaPrincipal.getId()), Long.toString(expiryTime), signatureValue },
					getTokenValiditySeconds(), request, response);
		} catch (UnsupportedEncodingException | GeneralSecurityException e) {
			logger.error("Error while trying to set the " + getCookieName() + " cookie", e);
		}
	}

	@Override
	protected UserDetails processAutoLoginCookie(String[] cookieTokens, HttpServletRequest request,
			HttpServletResponse response) throws RememberMeAuthenticationException, UsernameNotFoundException {
		if (cookieTokens == null || cookieTokens.length != COOKIE_TOKENS) {
			throw new InvalidCookieException("Cookie token did not contain " + COOKIE_TOKENS
					+ " tokens, but contained '" + Arrays.asList(cookieTokens) + "'");
		}

		long tokenExpiryTime;

		try {
			tokenExpiryTime = new Long(cookieTokens[1]).longValue();
		} catch (NumberFormatException nfe) {
			throw new InvalidCookieException(
					"Cookie token[1] did not contain a valid number (contained '"
							+ cookieTokens[1] + "')");
		}

		if (tokenExpiryTime < System.currentTimeMillis()) {
			throw new InvalidCookieException("Cookie token[1] has expired (expired on '"
					+ new Date(tokenExpiryTime) + "'; current time is '" + new Date()
					+ "')");
		}		
		
		String userId = null;
		UaaUser retrieveUserById = null;
		
		try {
			userId = decrypt(cookieTokens[0]);
			retrieveUserById = this.uaaUserDatabase.retrieveUserById(userId);
		} catch (UnsupportedEncodingException | GeneralSecurityException e) {
			throw new InvalidCookieException(String.format("Cookie token[0] contains an invalid user id '%s'", userId));
		}
		
		if (retrieveUserById == null) {
			throw new InvalidCookieException(String.format("Cookie token[0] contains an unknown user id '%s'", userId));
		}
		
		String expectedTokenSignature = makeTokenSignature(retrieveUserById.getId(), tokenExpiryTime
				, retrieveUserById.getModified()
				, request.getHeader(USER_AGENT_HEADER_NAME));
		
		if (!expectedTokenSignature.equals(cookieTokens[2])) {
			throw new InvalidCookieException("Cookie token[2] contained signature '"
					+ cookieTokens[2] + "' but expected '" + expectedTokenSignature + "'");
		}
		
		return new UaaUserDetails(retrieveUserById);
	}
	
	@Override
	protected Authentication createSuccessfulAuthentication(HttpServletRequest request, UserDetails user) {
		UaaUserDetails uaaUserDetails = (UaaUserDetails) user;
		UaaPrincipal uaaPrincipal = new UaaPrincipal(uaaUserDetails.getUser());
		return new RememberMeAuthenticationToken(getKey(), uaaPrincipal, user.getAuthorities());
	}
	
	/**
	 * Decrypt the incoming string parameter
	 * 
	 * @param data
	 * @return
	 * @throws UnsupportedEncodingException
	 * @throws GeneralSecurityException
	 */
	private String decrypt(String data) throws UnsupportedEncodingException, GeneralSecurityException {
		Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
		cipher.init(Cipher.DECRYPT_MODE, this.secret, this.ivParameterSpec);
		return new String(cipher.doFinal(Base64.getDecoder().decode(data.getBytes(UTF_8_CHARSET))), UTF_8_CHARSET);
	}

	/**
	 * Encrypt the incoming string parameter 
	 *
	 * @param data
	 * @return
	 * @throws UnsupportedEncodingException
	 * @throws GeneralSecurityException
	 */
	private String encrypt(String data) throws UnsupportedEncodingException, GeneralSecurityException {
		Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
		cipher.init(Cipher.ENCRYPT_MODE, this.secret, this.ivParameterSpec);
		return new String(Base64.getEncoder().encode(cipher.doFinal(data.getBytes(UTF_8_CHARSET))), UTF_8_CHARSET);
	}
	
    /**
     * Calculates the digital signature to be put in the cookie :SHA256("userid:tokenExpiryTime:modified:userAgent:key")
     *  
	 * @param id
	 * @param tokenExpiryTime
	 * @param modified
	 * @param userAgent
	 * @return
	 */
	private String makeTokenSignature(String id, long tokenExpiryTime, Date modified, String userAgent) {
		try {
			String data = String.format("%s:%d:%d:%s:%s", id, tokenExpiryTime, modified.getTime(), userAgent != null ? userAgent : "", getKey());
			MessageDigest digest = MessageDigest.getInstance(MESSAGE_DIGEST_ALGORITHM);
			return new String(Hex.encode(digest.digest(data.getBytes(UTF_8_CHARSET))));
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("No " + MESSAGE_DIGEST_ALGORITHM + " algorithm available!");
		} catch (UnsupportedEncodingException e) {
			throw new IllegalStateException("An error has occured while making the token signature", e);
		}
	}
}