package org.cloudfoundry.identity.uaa;/*
 * Copyright 2012-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportResource;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.web.context.request.RequestContextListener;

/**
 * @author Haytham Mohamed
 **/

@SpringBootApplication
@EnableWebSecurity
public class UaaBootApplication {

	public static void main(String... args) {
		SpringApplication.run(UaaBootApplication.class, args);
	}

	@Configuration
	@ImportResource({"classpath*:spring-servlet.xml"})
	public static class XMLConfigs {

	}

	@Bean
	public RequestContextListener requestContextListener(){
		return new RequestContextListener();
	}
}
