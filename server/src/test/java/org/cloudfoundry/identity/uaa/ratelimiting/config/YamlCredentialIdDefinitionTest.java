package org.cloudfoundry.identity.uaa.ratelimiting.config;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class YamlCredentialIdDefinitionTest {

    @Test
    void from() {
        assertNull( YamlCredentialIdDefinition.from( null ) );
        assertNull( YamlCredentialIdDefinition.from( "  " ) ); // a little testing to imply usage of StringUtils.normalizeToNull
        assertValues( "Fred", null, YamlCredentialIdDefinition.from( " Fred " ) );
        assertValues( "Fred", null, YamlCredentialIdDefinition.from( "Fred:" ) );
        assertValues( "Redish", "Yellow", YamlCredentialIdDefinition.from( " Redish : Yellow " ) );

    }

    private void assertValues( String expectedKey, String expectedPostKeyConfig, YamlCredentialIdDefinition definition ) {
        assertNotNull( definition, expectedKey );
        assertEquals( expectedKey, definition.getKey() );
        assertEquals( expectedPostKeyConfig, definition.getPostKeyConfig(), expectedKey );
    }
}