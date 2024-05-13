package org.cloudfoundry.identity.uaa.oauth.client.http.converter;

import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.BadClientCredentialsException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.OAuth2Exception;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.mock.http.MockHttpInputMessage;
import org.springframework.mock.http.MockHttpOutputMessage;

import java.io.IOException;
import java.util.Collections;

import static org.junit.Assert.*;

public class FormOAuth2ExceptionHttpMessageTest {

  FormOAuth2ExceptionHttpMessageConverter converter;
  FormOAuth2AccessTokenMessageConverter auth2AccessTokenMessageConverter;

  @Before
  public void setUp() throws Exception {
    converter = new FormOAuth2ExceptionHttpMessageConverter();
    auth2AccessTokenMessageConverter = new FormOAuth2AccessTokenMessageConverter();
  }

  @Test
  public void canRead() {
    assertTrue(converter.canRead(new OAuth2Exception("").getClass(), MediaType.APPLICATION_FORM_URLENCODED));
    assertFalse(auth2AccessTokenMessageConverter.canRead(new BadClientCredentialsException().getClass(), MediaType.APPLICATION_FORM_URLENCODED));
  }

  @Test
  public void canWrite() {
    assertTrue(converter.canWrite(new OAuth2Exception("").getClass(), MediaType.APPLICATION_FORM_URLENCODED));
    assertFalse(auth2AccessTokenMessageConverter.canWrite(new BadClientCredentialsException().getClass(), MediaType.APPLICATION_FORM_URLENCODED));
  }

  @Test
  public void getSupportedMediaTypes() {
    assertEquals(Collections.singletonList(MediaType.APPLICATION_FORM_URLENCODED), converter.getSupportedMediaTypes());
  }

  @Test
  public void read() throws IOException {
    assertNotNull(converter.read(new OAuth2Exception("").getClass(), new MockHttpInputMessage("".getBytes())));
  }

  @Test(expected = UnsupportedOperationException.class)
  public void writeInternal() throws IOException {
    auth2AccessTokenMessageConverter.writeInternal(new DefaultOAuth2AccessToken(""), new MockHttpOutputMessage());
  }

  @Test
  public void write() throws IOException {
    HttpOutputMessage outputMessage = new MockHttpOutputMessage();
    OAuth2Exception e = new BadClientCredentialsException();
    e.addAdditionalInformation("key", "value");
    converter.write(e, MediaType.APPLICATION_FORM_URLENCODED, outputMessage);
    assertNotNull(outputMessage.getBody());
    assertEquals("error=invalid_client&error_description=Bad+client+credentials&key=value", outputMessage.getBody().toString());
  }
}