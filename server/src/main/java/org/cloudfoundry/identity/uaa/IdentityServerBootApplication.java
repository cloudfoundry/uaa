/*
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
package org.cloudfoundry.identity.uaa;

import org.cloudfoundry.identity.uaa.cypto.EncryptionProperties;
import org.cloudfoundry.identity.uaa.message.util.FakeJavaMailSender;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.javamail.JavaMailSender;

/**
 * @author Haytham Mohamed
 **/

@SpringBootApplication
@EnableConfigurationProperties(EncryptionProperties.class)
public class IdentityServerBootApplication {

	public static void main(String[] args) {
		SpringApplication.run(IdentityServerBootApplication.class, args);
	}

	@Bean
	public JdbcTemplate jdbcTemplate() {
		return new JdbcTemplate();
	}

	@ConditionalOnMissingBean(JavaMailSender.class)
	@Bean
	public FakeJavaMailSender fakeJavaMailSender() {
		return new FakeJavaMailSender();
	}
}
