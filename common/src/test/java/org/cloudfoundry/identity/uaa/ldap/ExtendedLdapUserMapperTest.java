package org.cloudfoundry.identity.uaa.ldap;

import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.ldap.ExtendedLdapUserMapper.SUBSTITUTE_MAIL_ATTR_NAME;
import static org.junit.Assert.assertEquals;

public class ExtendedLdapUserMapperTest  {

    @Test
    public void testConfigureMailAttribute() throws Exception {
        ExtendedLdapUserMapper mapper = new ExtendedLdapUserMapper();
        mapper.setMailAttributeName("mail");
        mapper.setMailSubstitute("{0}@substitute.org");
        mapper.setMailSubstituteOverridesLdap(true);
        Map<String, String[]> records = new HashMap<>();
        String result = mapper.configureMailAttribute("marissa", records);
        assertEquals(SUBSTITUTE_MAIL_ATTR_NAME, result);
        assertEquals("marissa@substitute.org", records.get(SUBSTITUTE_MAIL_ATTR_NAME)[0]);

        mapper.setMailSubstituteOverridesLdap(false);
        result = mapper.configureMailAttribute("marissa", records);
        assertEquals(SUBSTITUTE_MAIL_ATTR_NAME, result);

        records.put("mail", new String[] {"marissa@test.org"});
        result = mapper.configureMailAttribute("marissa", records);
        assertEquals("mail", result);
    }
}