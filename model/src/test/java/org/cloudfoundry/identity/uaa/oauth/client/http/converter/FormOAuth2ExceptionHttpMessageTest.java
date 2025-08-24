package org.cloudfoundry.identity.uaa.oauth.client.http.converter;

import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.BadClientCredentialsException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.OAuth2Exception;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.mock.http.MockHttpInputMessage;
import org.springframework.mock.http.MockHttpOutputMessage;

import java.io.IOException;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

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
        assertThat(converter.getSupportedMediaTypes()).isEqualTo(Collections.singletonList(MediaType.APPLICATION_FORM_URLENCODED));
    }

    @Test
    void read() throws IOException {
        assertThat(converter.read(OAuth2Exception.class, new MockHttpInputMessage("".getBytes()))).isNotNull();
    }

    @Test
    void writeInternal() {
        assertThatExceptionOfType(UnsupportedOperationException.class).isThrownBy(() ->
                auth2AccessTokenMessageConverter.writeInternal(new DefaultOAuth2AccessToken(""), new MockHttpOutputMessage()));
    }

    @Test
    void write() throws IOException {
        HttpOutputMessage outputMessage = new MockHttpOutputMessage();
        OAuth2Exception e = new BadClientCredentialsException();
        e.addAdditionalInformation("key", "value");
        converter.write(e, MediaType.APPLICATION_FORM_URLENCODED, outputMessage);
        assertThat(outputMessage.getBody()).hasToString("error=invalid_client&error_description=Bad+client+credentials&key=value");
    }
}
