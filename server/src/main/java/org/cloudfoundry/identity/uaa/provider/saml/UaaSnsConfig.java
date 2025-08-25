package org.cloudfoundry.identity.uaa.provider.saml;

import com.ge.iam.sns.service.SnsService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

/**
 * Configuration for UAA-to-SNS integration
 */
@Configuration
@ComponentScan(basePackages = { "com.ge.iam.sns", "com.ge.iam.sqs" })
public class UaaSnsConfig {

    private static final Logger logger = LoggerFactory.getLogger(UaaSnsConfig.class);

    /**
     * Create the UserAttributeChangesSnsHandler bean, injecting the SnsService from
     * iam-k8s-utils
     *
     * @param snsService The SNS service implementation from iam-k8s-utils
     * @return A configured UserAttributeChangesSnsHandler
     */
    @Bean
    public UserAttributeChangesSnsHandler userAttributeChangesSnsHandler(SnsService snsService) {
        logger.info("Creating UserAttributeChangesSnsHandler with SNS service");
        return new UserAttributeChangesSnsHandler(snsService);
    }
}
