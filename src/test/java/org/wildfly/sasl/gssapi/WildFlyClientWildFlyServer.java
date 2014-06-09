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

import static org.wildfly.sasl.gssapi.JAASUtil.loginClient;
import static org.wildfly.sasl.gssapi.JAASUtil.loginServer;

import java.util.Collections;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslServer;

import org.junit.AfterClass;
import org.junit.BeforeClass;

/**
 * Test a WildFLy client can authenticate against a WildFly server.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class WildFlyClientWildFlyServer extends BaseGssapiTests {
    private static Subject clientSubject;
    private static Subject serverSubject;

    @BeforeClass
    public static void initialise() throws LoginException {
        clientSubject = loginClient();
        serverSubject = loginServer();
    }

    @AfterClass
    public static void destroy() {
        clientSubject = null;
        serverSubject = null;
    }

    @Override
    protected SaslClient getSaslClient(final boolean authServer, final VerificationMode mode) throws Exception {
        Map<String, String> props = Collections.emptyMap();
        SaslClient baseClient = createClient(clientSubject, true, authServer, mode, props);

        return new SubjectWrappingSaslClient(baseClient, clientSubject);
    }

    @Override
    protected SaslServer getSaslServer(final VerificationMode mode) throws Exception {
        Map<String, String> props = Collections.emptyMap();
        SaslServer baseServer = createServer(serverSubject, true, mode, props);

        return new SubjectWrappingSaslServer(baseServer, serverSubject);
    }

}
