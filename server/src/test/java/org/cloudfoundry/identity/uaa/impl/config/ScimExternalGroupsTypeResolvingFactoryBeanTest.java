package org.cloudfoundry.identity.uaa.impl.config;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

public class ScimExternalGroupsTypeResolvingFactoryBeanTest {

    @Test
    public void resultingExternalGroupsMap_withExternalGroupExtraSpaces() {
        List<String> internalToExternalGroups = Arrays.asList("acme|   cn=Engineering,ou=groups,dc=example,dc=com cn=HR,ou=groups,dc=example,dc=com   cn=mgmt,ou=groups,dc=example,dc=com ",
            "acme.dev|cn=Engineering,ou=groups,dc=example,dc=com  ");

        ScimExternalGroupsTypeResolvingFactoryBean scimExternalGroupsTypeResolvingFactoryBean = new ScimExternalGroupsTypeResolvingFactoryBean(internalToExternalGroups);
        Map<String, Map<String, List>> externalGroups = scimExternalGroupsTypeResolvingFactoryBean.getExternalGroups();
        assertThat(externalGroups.keySet(), containsInAnyOrder(OriginKeys.LDAP));
        assertThat(externalGroups.get(OriginKeys.LDAP).keySet(),
            containsInAnyOrder("cn=Engineering,ou=groups,dc=example,dc=com", "cn=HR,ou=groups,dc=example,dc=com", "cn=mgmt,ou=groups,dc=example,dc=com"));
    }

    @Test
    public void canAddExternalGroupsWithOrigin() {
        List<String> internalToExternalGroups = Arrays.asList("acme|cn=Engineering,ou=groups,dc=example,dc=com cn=HR,ou=groups,dc=example,dc=com cn=mgmt,ou=groups,dc=example,dc=com|uaa",
            "acme.dev|cn=Engineering,ou=groups,dc=example,dc=com|uaa");

        ScimExternalGroupsTypeResolvingFactoryBean scimExternalGroupsTypeResolvingFactoryBean = new ScimExternalGroupsTypeResolvingFactoryBean(internalToExternalGroups);
        Map<String, Map<String, List>> externalGroups = scimExternalGroupsTypeResolvingFactoryBean.getExternalGroups();
        assertThat(externalGroups.keySet(), containsInAnyOrder(OriginKeys.UAA));
    }

    @Test
    public void cannotAddInternalGroupsThatMapToNothing() {
        List<String> internalToExternalGroups = Arrays.asList("acme|", "acme.dev");

        ScimExternalGroupsTypeResolvingFactoryBean scimExternalGroupsTypeResolvingFactoryBean = new ScimExternalGroupsTypeResolvingFactoryBean(internalToExternalGroups);
        Map<String, Map<String, List>> externalGroups = scimExternalGroupsTypeResolvingFactoryBean.getExternalGroups();
        assertThat(externalGroups.size(), is(0));
    }
}
