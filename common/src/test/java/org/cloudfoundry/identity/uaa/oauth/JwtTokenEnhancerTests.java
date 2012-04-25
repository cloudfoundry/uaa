/**
 * Cloud Foundry 2012.02.03 Beta Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 * 
 * This product is licensed to you under the Apache License, Version 2.0 (the "License"). You may not use this product
 * except in compliance with the License.
 * 
 * This product includes a number of subcomponents with separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the subcomponent's license, as noted in the LICENSE file.
 */
package org.cloudfoundry.identity.uaa.oauth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationTestFactory;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

/**
 * @author Dave Syer
 * @author Luke Taylor
 */
public class JwtTokenEnhancerTests {

	private JwtTokenEnhancer tokenEnhancer;

	private UaaAuthentication userAuthentication;

	@Before
	public void setUp() throws Exception {
		tokenEnhancer = new JwtTokenEnhancer();
		userAuthentication = UaaAuthenticationTestFactory.getAuthentication("foo@bar.com", "Foo Bar", "foo@bar.com");
	}

	@Test
	public void testEnhanceAccessToken() {
		OAuth2Authentication authentication = new OAuth2Authentication(
				new AuthorizationRequest("foo", null, null, null), userAuthentication);
		OAuth2AccessToken token = tokenEnhancer.enhance(new DefaultOAuth2AccessToken("FOO"), authentication);
		assertNotNull(token.getValue());
	}


	@Test
	public void rsaKeyCreatesValidRsaSignedTokens() throws Exception {
		String rsaKey = " -----BEGIN RSA PRIVATE KEY-----  \n" +
				"  MIIBywIBAAJhAOTeb4AZ+NwOtPh+ynIgGqa6UWNVe6JyJi+loPmPZdpHtzoqubnC \n" +
				" wEs6JSiSZ3rButEAw8ymgLV6iBY02hdjsl3h5Z0NWaxx8dzMZfXe4EpfB04ISoqq\n" +
				"    hZCxchvuSDP4eQIDAQABAmEAqUuYsuuDWFRQrZgsbGsvC7G6zn3HLIy/jnM4NiJK\n" +
				" t0JhWNeN9skGsR7bqb1Sak2uWqW8ZqnqgAC32gxFRYHTavJEk6LTaHWovwDEhPqc\n" +
				" Zs+vXd6tZojJQ35chR/slUEBAjEA/sAd1oFLWb6PHkaz7r2NllwUBTvXL4VcMWTS\n" +
				" pN+5cU41i9fsZcHw6yZEl+ZCicDxAjEA5f3R+Bj42htNI7eylebew1+sUnFv1xT8\n" +
				" jlzxSzwVkoZo+vef7OD6OcFLeInAHzAJAjEAs6izolK+3ETa1CRSwz0lPHQlnmdM\n" +
				" Y/QuR5tuPt6U/saEVuJpkn4LNRtg5qt6I4JRAjAgFRYTG7irBB/wmZFp47izXEc3\n" +
				" gOdvA1hvq3tlWU5REDrYt24xpviA0fvrJpwMPbECMAKDKdiDi6Q4/iBkkzNMefA8\n" +
				"  7HX27b9LR33don/1u/yvzMUo+lrRdKAFJ+9GPE9XFA== \n" +
				"-----END RSA PRIVATE KEY----- ";
		tokenEnhancer.setSigningKey(rsaKey);
		OAuth2Authentication authentication = new OAuth2Authentication(
				new AuthorizationRequest("foo", null, null, null), userAuthentication);
		OAuth2AccessToken token = tokenEnhancer.enhance(new DefaultOAuth2AccessToken("FOO"), authentication);
		JwtHelper.decodeAndVerify(token.getValue(), new RsaVerifier(rsaKey));
	}

	@Test
	public void publicKeyStringIsReturnedFromTokenKeyEndpoint() throws Exception {
		tokenEnhancer.setVerifierKey("someKey");
		assertEquals("someKey", tokenEnhancer.getKey());
	}

	@Test(expected=IllegalStateException.class)
	public void keysNotMatchingWithMacSigner() throws Exception {
		tokenEnhancer.setSigningKey("aKey");
		tokenEnhancer.setVerifierKey("someKey");
		tokenEnhancer.afterPropertiesSet();
	}

}
