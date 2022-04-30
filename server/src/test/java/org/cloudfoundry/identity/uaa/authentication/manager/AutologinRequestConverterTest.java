package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.login.AutologinRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AutologinRequestConverterTest {

  private List<String> jsonMediaType = Arrays.asList(MediaType.APPLICATION_JSON_VALUE);
  private List<String> htmlMediaType = Arrays.asList(MediaType.APPLICATION_XHTML_XML_VALUE);

  private AutologinRequest autologinRequest;

  private AutologinRequestConverter autologinRequestConverter;

  private HttpInputMessage inputMessage;

  private HttpHeaders httpHeaders;

  @BeforeEach
  void setUp() {
    autologinRequest = new AutologinRequest();
    autologinRequestConverter = new AutologinRequestConverter();
    inputMessage = mock(HttpInputMessage.class);
    httpHeaders = mock(HttpHeaders.class);
    when(inputMessage.getHeaders()).thenReturn(httpHeaders);
  }

  @Test
  void supports() {
    Object newObject = new Object();
    assertFalse(autologinRequestConverter.supports(newObject.getClass()));
    assertTrue(autologinRequestConverter.supports(autologinRequest.getClass()));
  }

  @Test
  void isJsonContent() {
    assertTrue(autologinRequestConverter.isJsonContent(jsonMediaType));
    assertFalse(autologinRequestConverter.isJsonContent(htmlMediaType));
  }

  @Test
  void readInternalNoJson() throws IOException {
    AutologinRequest autologin = autologinRequestConverter.readInternal(autologinRequest.getClass(), inputMessage);
    assertNotNull(autologin);
  }

  @Test
  void readInternalFromJson() throws IOException {
    InputStream inputStream = new ByteArrayInputStream("{ \"username\": \"user\",\"password\": \"pwd\" }".getBytes("utf-8"));
    when(httpHeaders.get(HttpHeaders.CONTENT_TYPE)).thenReturn(jsonMediaType);
    when(inputMessage.getBody()).thenReturn(inputStream);
    AutologinRequest autologin = autologinRequestConverter.readInternal(autologinRequest.getClass(), inputMessage);
    assertNotNull(autologin);
    assertEquals("user", autologin.getUsername());
    assertEquals("pwd", autologin.getPassword());
  }

  @Test
  void writeInternal() throws IOException {
    OutputStream outputStream = mock(OutputStream.class);
    HttpOutputMessage outputMessage = mock(HttpOutputMessage.class);
    when(outputMessage.getHeaders()).thenReturn(httpHeaders);
    when(outputMessage.getBody()).thenReturn(outputStream);
    autologinRequest.setPassword("pwd");
    autologinRequest.setUsername("user");
    autologinRequestConverter.writeInternal(autologinRequest, outputMessage);
    verify(outputMessage, times(2)).getHeaders();
    verify(outputMessage, times(1)).getBody();
  }
}