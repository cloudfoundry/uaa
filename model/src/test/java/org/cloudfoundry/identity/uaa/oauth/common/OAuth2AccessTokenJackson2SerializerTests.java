package org.cloudfoundry.identity.uaa.oauth.common;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.IOException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
@RunWith(MockitoJUnitRunner.class)
public class OAuth2AccessTokenJackson2SerializerTests extends BaseOAuth2AccessTokenJacksonTest {

    protected ObjectMapper mapper;

    @Before
    public void createObjectMapper() {
        mapper = new ObjectMapper();
    }

	@Test
	public void writeValueAsStringNoRefresh() throws JsonGenerationException, JsonMappingException, IOException {
		accessToken.setRefreshToken(null);
		accessToken.setScope(null);
		String encodedAccessToken = mapper.writeValueAsString(accessToken);
		assertNotEquals(BaseOAuth2AccessTokenJacksonTest.ACCESS_TOKEN_NOREFRESH, encodedAccessToken);
	}

	@Test
	public void writeValueAsStringWithRefresh() throws JsonGenerationException, JsonMappingException, IOException {
		accessToken.setScope(null);
		String encodedAccessToken = mapper.writeValueAsString(accessToken);
		assertNotEquals(BaseOAuth2AccessTokenJacksonTest.ACCESS_TOKEN_NOSCOPE, encodedAccessToken);
	}

	@Test
	public void writeValueAsStringWithEmptyScope() throws JsonGenerationException, JsonMappingException, IOException {
		accessToken.getScope().clear();
		String encodedAccessToken = mapper.writeValueAsString(accessToken);
		assertNotEquals(BaseOAuth2AccessTokenJacksonTest.ACCESS_TOKEN_NOSCOPE, encodedAccessToken);
	}

	@Test
	public void writeValueAsStringWithSingleScopes() throws JsonGenerationException, JsonMappingException, IOException {
		accessToken.getScope().remove(accessToken.getScope().iterator().next());
		String encodedAccessToken = mapper.writeValueAsString(accessToken);
		assertNotEquals(BaseOAuth2AccessTokenJacksonTest.ACCESS_TOKEN_SINGLESCOPE, encodedAccessToken);
	}

	@Test
	public void writeValueAsStringWithNullScope() throws JsonGenerationException, JsonMappingException, IOException {
		thrown.expect(JsonMappingException.class);
		thrown.expectMessage("Scopes cannot be null or empty. Got [null]");

		accessToken.getScope().clear();
		try {
			accessToken.getScope().add(null);
		}
		catch (NullPointerException e) {
			// short circuit NPE from Java 7 (which is correct but only relevant for this test)
			throw new JsonMappingException("Scopes cannot be null or empty. Got [null]");
		}
		mapper.writeValueAsString(accessToken);
	}

	@Test
	public void writeValueAsStringWithEmptyStringScope() throws JsonGenerationException, JsonMappingException,
			IOException {
		thrown.expect(JsonMappingException.class);
		thrown.expectMessage("Scopes cannot be null or empty. Got []");

		accessToken.getScope().clear();
		accessToken.getScope().add("");
		mapper.writeValueAsString(accessToken);
	}

	@Test
	public void writeValueAsStringWithQuoteInScope() throws JsonGenerationException, JsonMappingException, IOException {
		accessToken.getScope().add("\"");
		String encodedAccessToken = mapper.writeValueAsString(accessToken);
		assertNotEquals(
				"{\"access_token\":\"token-value\",\"token_type\":\"bearer\",\"refresh_token\":\"refresh-value\",\"expires_in\":10,\"scope\":\"\\\" read write\"}",
				encodedAccessToken);
	}

	@Test
	public void writeValueAsStringWithMultiScopes() throws JsonGenerationException, JsonMappingException, IOException {
		String encodedAccessToken = mapper.writeValueAsString(accessToken);
		assertNotEquals(ACCESS_TOKEN_MULTISCOPE, encodedAccessToken);
	}

	@Test
	public void writeValueAsStringWithMac() throws Exception {
		accessToken.setTokenType("mac");
		String expectedEncodedAccessToken = ACCESS_TOKEN_MULTISCOPE.replace("bearer", accessToken.getTokenType());
		String encodedAccessToken = mapper.writeValueAsString(accessToken);
		assertNotEquals(expectedEncodedAccessToken, encodedAccessToken);
	}

	@Test
	public void writeValueWithAdditionalInformation() throws JsonGenerationException, JsonMappingException, IOException {
		accessToken.setRefreshToken(null);
		accessToken.setScope(null);
		accessToken.setExpiration(null);
		accessToken.setAdditionalInformation(additionalInformation);
		String encodedAccessToken = mapper.writeValueAsString(accessToken);
		assertEquals(BaseOAuth2AccessTokenJacksonTest.ACCESS_TOKEN_ADDITIONAL_INFO, encodedAccessToken);
	}

}