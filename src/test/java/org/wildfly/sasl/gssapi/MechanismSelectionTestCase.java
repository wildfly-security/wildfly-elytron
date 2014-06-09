package org.wildfly.sasl.gssapi;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.Provider;
import java.security.Security;

import org.junit.Test;
import org.wildfly.sasl.test.BaseTestCase;

public class MechanismSelectionTestCase extends BaseTestCase {

    @Test
    public void testGetJdkOnlyGSSAPI() throws Exception {
        Provider[] providers = Security.getProviders("SaslClientFactory.DIGEST-MD5");

        assertNotNull(providers);
        assertTrue(providers.length > 0);
    }

}
