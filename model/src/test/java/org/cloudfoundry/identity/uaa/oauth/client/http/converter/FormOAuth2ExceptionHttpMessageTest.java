package org.cloudfoundry.identity.uaa.oauth.client.http.converter;

import org.assertj.core.api.InstanceOfAssertFactories;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.BadClientCredentialsException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidClientException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.OAuth2Exception;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.mock.http.MockHttpInputMessage;
import org.springframework.mock.http.MockHttpOutputMessage;

import java.nio.charset.StandardCharsets;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class FormOAuth2ExceptionHttpMessageTest {

    FormOAuth2ExceptionHttpMessageConverter converter;
    FormOAuth2AccessTokenMessageConverter auth2AccessTokenMessageConverter;

    @BeforeEach
    void setUp() {
        converter = new FormOAuth2ExceptionHttpMessageConverter();
        auth2AccessTokenMessageConverter = new FormOAuth2AccessTokenMessageConverter();
    }

    @Test
    void canRead() {
        assertThat(converter.canRead(OAuth2Exception.class, MediaType.APPLICATION_FORM_URLENCODED)).isTrue();
        assertThat(auth2AccessTokenMessageConverter.canRead(BadClientCredentialsException.class, MediaType.APPLICATION_FORM_URLENCODED)).isFalse();
    }

    @Test
    void canWrite() {
        assertThat(converter.canWrite(OAuth2Exception.class, MediaType.APPLICATION_FORM_URLENCODED)).isTrue();
        assertThat(auth2AccessTokenMessageConverter.canWrite(BadClientCredentialsException.class, MediaType.APPLICATION_FORM_URLENCODED)).isFalse();
    }

    @Test
    void getSupportedMediaTypes() {
        assertThat(converter.getSupportedMediaTypes()).containsExactlyElementsOf(Collections.singletonList(MediaType.APPLICATION_FORM_URLENCODED));
    }

    @Test
    void read() throws Exception {
        assertThat(converter.read(OAuth2Exception.class, new MockHttpInputMessage("".getBytes()))).isNotNull();
    }

    @Test
    void readFormEncodedException() throws Exception {
        MockHttpInputMessage input = new MockHttpInputMessage(
                "error=invalid_client&error_description=Bad+client+credentials".getBytes(StandardCharsets.UTF_8));
        input.getHeaders().setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        OAuth2Exception exception = converter.read(OAuth2Exception.class, input);

        assertThat(exception)
                .isInstanceOf(InvalidClientException.class)
                .hasMessage("Bad client credentials");
    }

    @Test
    void readFormEncodedAccessToken() throws Exception {
        MockHttpInputMessage input = new MockHttpInputMessage(
                "access_token=the_token&token_type=bearer&scope=openid+profile".getBytes(StandardCharsets.UTF_8));
        input.getHeaders().setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        OAuth2AccessToken token = auth2AccessTokenMessageConverter.read(OAuth2AccessToken.class, input);

        assertThat(token.getValue()).isEqualTo("the_token");
        assertThat(token.getTokenType()).isEqualTo("bearer");
        assertThat(token.getScope()).containsExactlyInAnyOrder("openid", "profile");
    }

    @Test
    void writeInternal() {
        assertThatThrownBy(() ->
                auth2AccessTokenMessageConverter.writeInternal(new DefaultOAuth2AccessToken(""), new MockHttpOutputMessage())).asInstanceOf(InstanceOfAssertFactories.throwable(UnsupportedOperationException.class));
    }

    @Test
    void write() throws Exception {
        HttpOutputMessage outputMessage = new MockHttpOutputMessage();
        OAuth2Exception e = new BadClientCredentialsException();
        e.addAdditionalInformation("key", "value");
        converter.write(e, MediaType.APPLICATION_FORM_URLENCODED, outputMessage);
        assertThat(outputMessage.getBody()).hasToString("error=invalid_client&error_description=Bad+client+credentials&key=value");
    }
}
