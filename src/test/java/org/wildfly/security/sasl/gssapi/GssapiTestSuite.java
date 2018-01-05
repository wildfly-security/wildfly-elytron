/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wildfly.security.sasl.gssapi;

import java.util.Map;

import org.jboss.logging.Logger;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;
import org.wildfly.security.sasl.gs2.Gs2SuiteChild;

/**
 * Test suite to run all GSSAPI and GS2 tests to allow various permutations of mechanism interaction to be verified.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@RunWith(Suite.class)
@SuiteClasses({
    GSSSecurityFactorySuiteChild.class,
    JdkClientJdkServerSuiteChild.class,
    JdkClientWildFlyServerSuiteChild.class,
    WildFlyClientJdkServerSuiteChild.class,
    WildFlyClientWildFlyServerSuiteChild.class,
    Gs2SuiteChild.class
})
public class GssapiTestSuite {

    private static Logger log = Logger.getLogger(GssapiTestSuite.class);

    public static TestKDC testKdc;
    public static String serverKeyTab;
    public static String serverUnboundKeyTab;

    @BeforeClass
    public static void startServers() {
        log.debug("Starting KDC...");
        testKdc = new TestKDC(true);
        testKdc.startDirectoryService();
        testKdc.startKDC();
        serverKeyTab = testKdc.generateKeyTab(BaseGssapiTests.SERVER_KEY_TAB,
                "sasl/test_server_1@WILDFLY.ORG", "servicepwd"
        );
        log.debug("serverKeyTab written to:" + serverKeyTab);
        serverUnboundKeyTab = testKdc.generateKeyTab(BaseGssapiTests.SERVER_UNBOUND_KEY_TAB,
                "sasl/test_server_1@WILDFLY.ORG", "servicepwd",
                "*@WILDFLY.ORG", "dummy" // existence required by IBM
        );
        log.debug("serverUnboundKeyTab written to:" + serverUnboundKeyTab);
    }

    @AfterClass
    public static void stopServers() {
        if (testKdc != null) {
            testKdc.stopAll();
            testKdc = null;
        }
    }
}
