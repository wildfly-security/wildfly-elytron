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
package org.wildfly.sasl.gssapi;

import org.jboss.logging.Logger;
import org.jboss.logmanager.log4j.BridgeRepositorySelector;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

/**
 * Test suite to run all GSSAPI tests to allow various permutations of mechanism interaction to be verified..
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@RunWith(Suite.class)
@SuiteClasses({
    JdkClientJdkServer.class,
    JdkClientWildFlyServer.class,
    WildFlyClientJdkServer.class,
    WildFlyClientWildFlyServer.class
})
public class GssapiTestSuite {

    private static Logger log = Logger.getLogger(GssapiTestSuite.class);

    static TestKDC testKdc;

    @BeforeClass
    public static void startServers() {
        log.debug("Start");
        new BridgeRepositorySelector().start();

        TestKDC testKdc = new TestKDC();
        testKdc.startDirectoryService();
        testKdc.startKDC();
        GssapiTestSuite.testKdc = testKdc;
    }

    @AfterClass
    public static void stopServers() {
        if (testKdc != null) {
            testKdc.stopAll();
            testKdc = null;
        }
    }

}
