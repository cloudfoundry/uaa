package org.cloudfoundry.identity.uaa.oauth.provider.config.xml;

import org.cloudfoundry.identity.uaa.oauth.client.resource.AuthorizationCodeResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.BaseOAuth2ProtectedResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.ClientCredentialsResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.ImplicitResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.ResourceOwnerPasswordResourceDetails;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.beans.factory.xml.XmlReaderContext;
import org.w3c.dom.Element;

import java.util.List;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class ResourceBeanDefinitionParserTest {

  private ResourceBeanDefinitionParser parser;
  private Element element;
  private ParserContext parserContext;
  private BeanDefinitionBuilder builder;
  private XmlReaderContext xmlReaderContext;

  @Before
  public void setUp() throws Exception {
    element = mock(Element.class);
    parserContext = mock(ParserContext.class);
    builder = mock(BeanDefinitionBuilder.class);
    xmlReaderContext = mock(XmlReaderContext.class);
    when(parserContext.getReaderContext()).thenReturn(xmlReaderContext);
    when(parserContext.getRegistry()).thenReturn(mock(BeanDefinitionRegistry.class));
    parser = new ResourceBeanDefinitionParser();
  }

  @Test
  public void getBeanClass() {
    assertEquals(BaseOAuth2ProtectedResourceDetails.class, parser.getBeanClass(element));
    when(element.getAttribute("type")).thenReturn("authorization_code");
    assertEquals(AuthorizationCodeResourceDetails.class, parser.getBeanClass(element));
    when(element.getAttribute("type")).thenReturn("implicit");
    assertEquals(ImplicitResourceDetails.class, parser.getBeanClass(element));
    when(element.getAttribute("type")).thenReturn("client_credentials");
    assertEquals(ClientCredentialsResourceDetails.class, parser.getBeanClass(element));
    when(element.getAttribute("type")).thenReturn("password");
    assertEquals(ResourceOwnerPasswordResourceDetails.class, parser.getBeanClass(element));
  }

  @Test
  public void doParseNoId() {
    parser.doParse(element, parserContext, builder);
    verify(xmlReaderContext).error("An id must be supplied on a resource element.", element);
  }

  @Test
  public void doParse() {
    when(element.getAttribute("id")).thenReturn("myId");
    parser.doParse(element, parserContext, builder);
    verify(builder, times(4)).addPropertyValue(anyString(), any(Object.class));
  }

  @Test
  public void doParseImplicit() {
    when(element.getAttribute("type")).thenReturn("implicit");
    when(element.getAttribute("id")).thenReturn("myId");
    when(element.getAttribute("scope")).thenReturn("one two");
    when(element.getAttribute("client-secret")).thenReturn("secret");
    when(element.getAttribute("user-authorization-uri")).thenReturn("client_credentials");
    when(element.getAttribute("client-authentication-scheme")).thenReturn("form");
    parser.doParse(element, parserContext, builder);
    verify(builder, times(8)).addPropertyValue(anyString(), any(Object.class));
  }

  @Test
  public void doParseImplicitNoUri() {
    when(element.getAttribute("type")).thenReturn("implicit");
    when(element.getAttribute("id")).thenReturn("myId");
    when(element.getAttribute("scope")).thenReturn("one two");
    when(element.getAttribute("client-id")).thenReturn("client_id");
    when(element.getAttribute("client-secret")).thenReturn("secret");
    when(element.getAttribute("client-authentication-scheme")).thenReturn("form");
    parser.doParse(element, parserContext, builder);
    verify(xmlReaderContext).error("An authorization URI must be supplied for a resource of type implicit", element);
    verify(builder, times(8)).addPropertyValue(anyString(), any(Object.class));
  }

  @Test
  public void doParseScopes() {
    when(element.getAttribute("id")).thenReturn("myId");
    when(element.getAttribute("scope")).thenReturn("one two");
    when(element.getAttribute("user-authorization-uri")).thenReturn("client_credentials");
    when(element.getAttribute("client-secret")).thenReturn("secret");
    when(element.getAttribute("client-authentication-scheme")).thenReturn("form");
    when(element.getAttribute("authentication-scheme")).thenReturn("form");
    parser.doParse(element, parserContext, builder);
    verify(builder, times(7)).addPropertyValue(anyString(), any(Object.class));
  }

  @Test
  public void doParsePassword() {
    when(element.getAttribute("type")).thenReturn("password");
    when(element.getAttribute("username")).thenReturn("userid");
    when(element.getAttribute("id")).thenReturn("myId");
    when(element.getAttribute("scope")).thenReturn("one two");
    when(element.getAttribute("user-authorization-uri")).thenReturn("client_credentials");
    when(element.getAttribute("client-secret")).thenReturn("secret");
    when(element.getAttribute("client-authentication-scheme")).thenReturn("form");
    when(element.getAttribute("pre-established-redirect-uri")).thenReturn("uri");
    when(element.getAttribute("require-immediate-authorization")).thenReturn("true");
    when(element.getAttribute("use-current-uri")).thenReturn("true");
    parser.doParse(element, parserContext, builder);
    verify(builder, times(11)).addPropertyValue(anyString(), any(Object.class));
  }

  @Test
  public void doStatic() throws Exception {
    ResourceBeanDefinitionParser.StringListFactoryBean stringListFactoryBean  = new ResourceBeanDefinitionParser.StringListFactoryBean("one,two");
    assertEquals(2, stringListFactoryBean.getObject().size());
    assertEquals("one", stringListFactoryBean.getObject().get(0));
    assertEquals("two", stringListFactoryBean.getObject().get(1));
    assertEquals(List.class, stringListFactoryBean.getObjectType());
    assertTrue(stringListFactoryBean.isSingleton());
  }

}
