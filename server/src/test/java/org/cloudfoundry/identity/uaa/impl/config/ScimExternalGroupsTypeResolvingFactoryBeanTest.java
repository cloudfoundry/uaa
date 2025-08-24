package org.cloudfoundry.identity.uaa.impl.config;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ScimExternalGroupsTypeResolvingFactoryBeanTest {

    @Test
    void resultingExternalGroupsMap_withExternalGroupExtraSpaces() {
        List<String> internalToExternalGroups = Arrays.asList("acme|   cn=Engineering,ou=groups,dc=example,dc=com cn=HR,ou=groups,dc=example,dc=com   cn=mgmt,ou=groups,dc=example,dc=com ",
                "acme.dev|cn=Engineering,ou=groups,dc=example,dc=com  ");

        ScimExternalGroupsTypeResolvingFactoryBean scimExternalGroupsTypeResolvingFactoryBean = new ScimExternalGroupsTypeResolvingFactoryBean(internalToExternalGroups);
        Map<String, Map<String, List>> externalGroups = scimExternalGroupsTypeResolvingFactoryBean.getExternalGroups();
        assertThat(externalGroups.keySet()).containsExactlyInAnyOrder(OriginKeys.LDAP);
        assertThat(externalGroups.get(OriginKeys.LDAP).keySet()).containsExactlyInAnyOrder("cn=Engineering,ou=groups,dc=example,dc=com", "cn=HR,ou=groups,dc=example,dc=com", "cn=mgmt,ou=groups,dc=example,dc=com");
    }

    @Test
    void canAddExternalGroupsWithOrigin() {
        List<String> internalToExternalGroups = Arrays.asList("acme|cn=Engineering,ou=groups,dc=example,dc=com cn=HR,ou=groups,dc=example,dc=com cn=mgmt,ou=groups,dc=example,dc=com|uaa",
                "acme.dev|cn=Engineering,ou=groups,dc=example,dc=com|uaa");

        ScimExternalGroupsTypeResolvingFactoryBean scimExternalGroupsTypeResolvingFactoryBean = new ScimExternalGroupsTypeResolvingFactoryBean(internalToExternalGroups);
        Map<String, Map<String, List>> externalGroups = scimExternalGroupsTypeResolvingFactoryBean.getExternalGroups();
        assertThat(externalGroups.keySet()).containsExactlyInAnyOrder(OriginKeys.UAA);
    }

    @Test
    void cannotAddInternalGroupsThatMapToNothing() {
        List<String> internalToExternalGroups = Arrays.asList("acme|", "acme.dev");

        ScimExternalGroupsTypeResolvingFactoryBean scimExternalGroupsTypeResolvingFactoryBean = new ScimExternalGroupsTypeResolvingFactoryBean(internalToExternalGroups);
        Map<String, Map<String, List>> externalGroups = scimExternalGroupsTypeResolvingFactoryBean.getExternalGroups();
        assertThat(externalGroups).isEmpty();
    }
}
