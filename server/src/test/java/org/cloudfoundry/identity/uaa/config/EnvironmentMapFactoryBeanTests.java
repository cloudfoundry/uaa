/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.config;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.cloudfoundry.identity.uaa.impl.config.EnvironmentMapFactoryBean;
import org.cloudfoundry.identity.uaa.impl.config.NestedMapPropertySource;
import org.junit.Test;
import org.springframework.core.env.StandardEnvironment;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * @author Dave Syer
 * 
 */
public class EnvironmentMapFactoryBeanTests
{

    @Test
    public void testDefaultProperties() throws Exception
    {
        EnvironmentMapFactoryBean factory = new EnvironmentMapFactoryBean();
        factory.setDefaultProperties(getProperties("{\"foo\":\"foo\"}"));
        Map<String, ?> properties = factory.getObject();
        assertEquals("foo", properties.get("foo"));
    }

    @Test
    public void testRawPlaceholderProperties() throws Exception
    {
        EnvironmentMapFactoryBean factory = new EnvironmentMapFactoryBean();
        factory.setDefaultProperties(getProperties("{\"foo\":\"${bar}\"}"));
        Map<String, ?> properties = factory.getObject();
        assertEquals("${bar}", properties.get("foo"));
    }

    @Test
    public void testPlaceholderProperties() throws Exception
    {
        EnvironmentMapFactoryBean factory = new EnvironmentMapFactoryBean();
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources()
                .addLast(new NestedMapPropertySource("override", getProperties("{\"bar\":\"${spam}\"}")));
        factory.setEnvironment(environment);
        factory.setDefaultProperties(getProperties("{\"foo\":\"baz\"}"));
        Map<String, ?> properties = factory.getObject();
        assertEquals("baz", properties.get("foo"));
        assertEquals("${spam}", properties.get("bar"));
    }

    @Test
    public void testOverrideProperties() throws Exception
    {
        EnvironmentMapFactoryBean factory = new EnvironmentMapFactoryBean();
        factory.setDefaultProperties(getProperties("{\"foo\":\"foo\"}"));
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources()
                .addLast(new NestedMapPropertySource("override", getProperties("{\"foo\":\"bar\"}")));
        factory.setEnvironment(environment);
        Map<String, ?> properties = factory.getObject();
        assertEquals("bar", properties.get("foo"));
    }
    
    @Test
    public void testPlaceholderResolutionForSimpleValue() throws Exception
    {
        EnvironmentMapFactoryBean factory = new EnvironmentMapFactoryBean();
        
        System.setProperty("some_env", "some_env_value");
        
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources()
        .addLast(new NestedMapPropertySource("override", getProperties("{\"foo\":\"${some_env}\"}")));
        
        
        factory.setEnvironment(environment);
        
        Map<String, ?> properties = factory.getObject();
        assertEquals("some_env_value", properties.get("foo"));
    }
    
    
    @Test
    public void testPlaceholderResolutionForListValue() throws Exception
    {
        EnvironmentMapFactoryBean factory = new EnvironmentMapFactoryBean();
        
        System.setProperty("some_env", "some_env_value");
        
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources()
        .addLast(new NestedMapPropertySource("override", getProperties("{\"foo\":[\"${some_env}\",\"bar2\"]}")));
        
        
        factory.setEnvironment(environment);
        
        Map<String, ?> properties = factory.getObject();
        Object val = properties.get("foo");
        assertTrue("The value must be of type list",val instanceof List);
        
        @SuppressWarnings("rawtypes")
        List asList = (List)val;
        assertEquals("some_env_value", asList.get(0));
    }

    @Test
    public void testPlaceholderResolutionForMapValue() throws Exception
    {
        EnvironmentMapFactoryBean factory = new EnvironmentMapFactoryBean();
        
        System.setProperty("some_env", "some_env_value");
        
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources()
        .addLast(new NestedMapPropertySource("override", getProperties("{\"fake-client\":{\"key1\": \"${some_env}\"}}")));
        
        
        factory.setEnvironment(environment);
        
        Map<String, ?> properties = factory.getObject();
        Object val = properties.get("fake-client");
        assertTrue("The value must be of type list",val instanceof Map);
        
        @SuppressWarnings("rawtypes")
        Map asMap = (Map)val;
        assertEquals("some_env_value", asMap.get("key1"));
    }

    @Test
    public void testPlaceholderResolutionForNoEnvSimpleValue() throws Exception
    {
        EnvironmentMapFactoryBean factory = new EnvironmentMapFactoryBean();
        
        System.setProperty("some_env", "some_env_value");
        
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources()
        .addLast(new NestedMapPropertySource("override", getProperties("{\"foo\":\"${spam}\"}")));
        
        
        factory.setEnvironment(environment);
        
        Map<String, ?> properties = factory.getObject();
        assertEquals("${spam}", properties.get("foo"));
    }
    
    
    @Test
    public void testPlaceholderResolutionForNoEnvListValue() throws Exception
    {
        EnvironmentMapFactoryBean factory = new EnvironmentMapFactoryBean();
        
        System.setProperty("some_env", "some_env_value");
        
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources()
        .addLast(new NestedMapPropertySource("override", getProperties("{\"foo\":[\"${spam}\",\"bar2\"]}")));
        
        
        factory.setEnvironment(environment);
        
        Map<String, ?> properties = factory.getObject();
        Object val = properties.get("foo");
        assertTrue("The value must be of type list",val instanceof List);
        
        @SuppressWarnings("rawtypes")
        List asList = (List)val;
        assertEquals("${spam}", asList.get(0));
    }

    @Test
    public void testPlaceholderResolutionForNoEnvMapValue() throws Exception
    {
        EnvironmentMapFactoryBean factory = new EnvironmentMapFactoryBean();
        
        System.setProperty("some_env", "some_env_value");
        
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources()
        .addLast(new NestedMapPropertySource("override", getProperties("{\"fake-client\":{\"key1\": \"${spam}\"}}")));
        
        
        factory.setEnvironment(environment);
        
        Map<String, ?> properties = factory.getObject();
        Object val = properties.get("fake-client");
        assertTrue("The value must be of type map",val instanceof Map);
        
        @SuppressWarnings("rawtypes")
        Map asMap = (Map)val;
        assertEquals("${spam}", asMap.get("key1"));
    }

    @Test
    public void testPlaceholderResolutionForSimpleNullValue() throws Exception
    {
        EnvironmentMapFactoryBean factory = new EnvironmentMapFactoryBean();
        
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources()
        .addLast(new NestedMapPropertySource("override", getProperties("{\"foo\":null}")));

        factory.setEnvironment(environment);

        Map<String, ?> properties = factory.getObject();
        assertNull(properties.get("foo"));
    }
    
    
    @Test
    public void testPlaceholderResolutionForListNullValue() throws Exception
    {
        EnvironmentMapFactoryBean factory = new EnvironmentMapFactoryBean();
        
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources()
        .addLast(new NestedMapPropertySource("override", getProperties("{\"foo\":[null,\"bar2\"]}")));

        factory.setEnvironment(environment);

        Map<String, ?> properties = factory.getObject();
        Object val = properties.get("foo");
        assertTrue("The value must be of type list",val instanceof List);
        
        @SuppressWarnings("rawtypes")
        List asList = (List)val;
        assertNull(asList.get(0));
    }

    @Test
    public void testPlaceholderResolutionForMapNullValue() throws Exception
    {
        EnvironmentMapFactoryBean factory = new EnvironmentMapFactoryBean();
        
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources()
        .addLast(new NestedMapPropertySource("override", getProperties("{\"fake-client\":{\"key1\": null}}")));

        factory.setEnvironment(environment);

        Map<String, ?> properties = factory.getObject();
        Object val = properties.get("fake-client");
        assertTrue("The value must be of type list",val instanceof Map);
        
        @SuppressWarnings("rawtypes")
        Map asMap = (Map)val;
        assertNull(asMap.get("key1"));
    }

    @SuppressWarnings("rawtypes")
    private Map<String, ?> getProperties(String input)
            throws JsonParseException, JsonMappingException, IOException
    {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(input, new TypeReference<HashMap>()
        {
        });
    }
    
    public static void main(String[] args) throws JsonProcessingException
    {
        ObjectMapper mapper = new ObjectMapper();
        Map<String,String> map = new HashMap<>();
        
        map.put("key", null);
        
        System.out.println(mapper.writeValueAsString(map));
    }
}
