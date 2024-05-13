package org.cloudfoundry.identity.uaa.oauth.common.exception;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InsufficientScopeException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidClientException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidGrantException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidRequestException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidScopeException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidTokenException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.OAuth2Exception;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.RedirectMismatchException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.UnauthorizedClientException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.UnsupportedGrantTypeException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.UserDeniedAuthorizationException;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class OAuth2ExceptionJackson2DeserializerTests {
	private static final String DETAILS = "some detail";
	private static ObjectMapper mapper;

	@BeforeClass
	public static void setUpClass() {
		mapper = new ObjectMapper();
	}

	@Test
	public void readValueInvalidGrant() throws Exception {
		String accessToken = createResponse(OAuth2Exception.INVALID_GRANT);
		InvalidGrantException result = (InvalidGrantException) mapper.readValue(accessToken, OAuth2Exception.class);
		assertEquals(DETAILS,result.getMessage());
		assertEquals(null,result.getAdditionalInformation());
	}

	@Test
	public void readValueInvalidRequest() throws Exception {
		String accessToken = createResponse(OAuth2Exception.INVALID_REQUEST);
		InvalidRequestException result = (InvalidRequestException) mapper.readValue(accessToken, OAuth2Exception.class);
		assertEquals(DETAILS,result.getMessage());
		assertEquals(null,result.getAdditionalInformation());
	}

	@Test
	public void readValueInvalidScope() throws Exception {
		String accessToken = createResponse(OAuth2Exception.INVALID_SCOPE);
		InvalidScopeException result = (InvalidScopeException) mapper.readValue(accessToken, OAuth2Exception.class);
		assertEquals(DETAILS,result.getMessage());
		assertEquals(null,result.getAdditionalInformation());
	}

	@Test
	public void readValueIsufficientScope() throws Exception {
		String accessToken = "{\"error\": \"insufficient_scope\", \"error_description\": \"insufficient scope\", \"scope\": \"bar foo\"}";
		InsufficientScopeException result = (InsufficientScopeException) mapper.readValue(accessToken, OAuth2Exception.class);
		assertEquals("insufficient scope",result.getMessage());
		assertEquals("bar foo",result.getAdditionalInformation().get("scope").toString());
	}

	@Test
	public void readValueUnsupportedGrantType() throws Exception {
		String accessToken = createResponse(OAuth2Exception.UNSUPPORTED_GRANT_TYPE);
		UnsupportedGrantTypeException result = (UnsupportedGrantTypeException) mapper.readValue(accessToken,
				OAuth2Exception.class);
		assertEquals(DETAILS,result.getMessage());
		assertEquals(null,result.getAdditionalInformation());
	}

	@Test
	public void readValueUnauthorizedClient() throws Exception {
		String accessToken = createResponse(OAuth2Exception.UNAUTHORIZED_CLIENT);
		UnauthorizedClientException result = (UnauthorizedClientException) mapper.readValue(accessToken,
				OAuth2Exception.class);
		assertEquals(DETAILS,result.getMessage());
		assertEquals(null,result.getAdditionalInformation());
	}

	@Test
	public void readValueAccessDenied() throws Exception {
		String accessToken = createResponse(OAuth2Exception.ACCESS_DENIED);
		UserDeniedAuthorizationException result = (UserDeniedAuthorizationException) mapper.readValue(accessToken,
				OAuth2Exception.class);
		assertEquals(DETAILS,result.getMessage());
		assertEquals(null,result.getAdditionalInformation());
	}

	@Test
	public void readValueRedirectUriMismatch() throws Exception {
		String accessToken = createResponse(OAuth2Exception.INVALID_GRANT, "Redirect URI mismatch.");
		RedirectMismatchException result = (RedirectMismatchException) mapper.readValue(accessToken,
				OAuth2Exception.class);
		assertEquals("Redirect URI mismatch.",result.getMessage());
		assertEquals(null,result.getAdditionalInformation());
	}

	@Test
	public void readValueInvalidToken() throws Exception {
		String accessToken = createResponse(OAuth2Exception.INVALID_TOKEN);
		InvalidTokenException result = (InvalidTokenException) mapper.readValue(accessToken, OAuth2Exception.class);
		assertEquals(DETAILS,result.getMessage());
		assertEquals(null,result.getAdditionalInformation());
	}

	@Test
	public void readValueUndefinedException() throws Exception {
		String accessToken = createResponse("notdefinedcode");
		OAuth2Exception result = mapper.readValue(accessToken, OAuth2Exception.class);
		assertEquals(DETAILS,result.getMessage());
		assertEquals(null,result.getAdditionalInformation());
	}

	@Test
	public void readValueInvalidClient() throws Exception {
		String accessToken = createResponse(OAuth2Exception.INVALID_CLIENT);
		InvalidClientException result = (InvalidClientException) mapper.readValue(accessToken, OAuth2Exception.class);
		assertEquals(DETAILS,result.getMessage());
		assertEquals(null,result.getAdditionalInformation());
	}

	@Test
	public void readValueWithAdditionalDetails() throws Exception {
		String accessToken = "{\"error\": \"invalid_client\", \"error_description\": \"some detail\", \"foo\": \"bar\"}";
		InvalidClientException result = (InvalidClientException) mapper.readValue(accessToken, OAuth2Exception.class);
		assertEquals(DETAILS,result.getMessage());
		assertEquals("{foo=bar}",result.getAdditionalInformation().toString());
	}

	@Test
	public void readValueWithObjects() throws Exception {
		String accessToken = "{\"error\": [\"invalid\",\"client\"], \"error_description\": {\"some\":\"detail\"}, \"foo\": [\"bar\"]}";
		OAuth2Exception result = mapper.readValue(accessToken, OAuth2Exception.class);
		assertEquals("{some=detail}",result.getMessage());
		assertEquals("{foo=[bar]}",result.getAdditionalInformation().toString());
	}

	// gh-594
	@Test
	public void readValueWithNullErrorDescription() throws Exception {
		OAuth2Exception ex = new OAuth2Exception(null);
		OAuth2Exception result = mapper.readValue(mapper.writeValueAsString(ex), OAuth2Exception.class);
		// Null error description defaults to error code when deserialized
		assertEquals(ex.getOAuth2ErrorCode(), result.getMessage());
	}

	private String createResponse(String error, String message) {
		return "{\"error\":\"" + error + "\",\"error_description\":\""+message+"\"}";
	}

	private String createResponse(String error) {
		return createResponse(error, DETAILS);
	}

}
