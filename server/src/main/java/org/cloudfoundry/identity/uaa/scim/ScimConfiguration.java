package org.cloudfoundry.identity.uaa.scim;

import org.cloudfoundry.identity.uaa.db.beans.DatabaseProperties;
import org.cloudfoundry.identity.uaa.resources.JoinAttributeNameMapper;
import org.cloudfoundry.identity.uaa.resources.SimpleAttributeNameMapper;
import org.cloudfoundry.identity.uaa.resources.jdbc.SimpleSearchQueryConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Map;

@Configuration
class ScimConfiguration {

    @Bean
    SimpleSearchQueryConverter scimUserQueryConverter(DatabaseProperties databaseProperties) {
        var converter = new SimpleSearchQueryConverter();
        var mapper = new SimpleAttributeNameMapper(Map.of(
                "emails\\.value", "email",
                "groups\\.display", "authorities",
                "phoneNumbers\\.value", "phoneNumber"
        ));
        converter.setAttributeNameMapper(mapper);
        converter.setDbCaseInsensitive(databaseProperties.isCaseinsensitive());
        return converter;
    }

    @Bean
    SimpleSearchQueryConverter scimJoinQueryConverter(DatabaseProperties databaseProperties) {
        var converter = new SimpleSearchQueryConverter();
        var mapper = new JoinAttributeNameMapper("u");
        converter.setAttributeNameMapper(mapper);
        converter.setDbCaseInsensitive(databaseProperties.isCaseinsensitive());
        return converter;
    }


}
