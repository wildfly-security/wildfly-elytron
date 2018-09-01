/*
 * Copyright 2018 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.auth.jaspi;

import static java.util.Collections.EMPTY_MAP;

import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;

import org.junit.Test;

/**
 * Test case covering secureResponse handling.
 *
 * secureResponse processing is different from validateResponse processing as all ServerAuthModules are called in reverse order only stopping
 * if one returns {@link AuthStatus.SEND_FAILURE} or throws {@link AuthException}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class AuthModuleSecureTest extends AuthModuleBase {

    /**
     * Where all ServerAuthModules return SEND_SUCCESS they should be called in the correct order and the final result is SEND_SUCCESS.
     */
    @Test
    public void testSendSuccess() throws Exception {
        final String registrationId = JaspiConfigurationBuilder.builder(LAYER, APP_CONTEXT)
            .setDescription(DESCRIPTION)
            .addAuthModuleFactory(() -> new TestServerAuthModule(AuthStatus.SEND_SUCCESS, callCounter, 3), Flag.REQUIRED, EMPTY_MAP)
            .addAuthModuleFactory(() -> new TestServerAuthModule(AuthStatus.SEND_SUCCESS, callCounter, 2), Flag.REQUIRED, EMPTY_MAP)
            .addAuthModuleFactory(() -> new TestServerAuthModule(AuthStatus.SEND_SUCCESS, callCounter, 1), Flag.REQUIRED, EMPTY_MAP)
            .register(authConfigFactory);

        test(AuthStatus.SEND_SUCCESS, 3, registrationId);
    }

    /**
     * Where one ServerAuthModule returns SEND_CONTINUE they should all be called in the correct order but the result is SEND_CONTINUE.
     */
    @Test
    public void testSendContinue() throws Exception {
        final String registrationId = JaspiConfigurationBuilder.builder(LAYER, APP_CONTEXT)
            .setDescription(DESCRIPTION)
            .addAuthModuleFactory(() -> new TestServerAuthModule(AuthStatus.SEND_SUCCESS, callCounter, 3), Flag.REQUIRED, EMPTY_MAP)
            .addAuthModuleFactory(() -> new TestServerAuthModule(AuthStatus.SEND_CONTINUE, callCounter, 2), Flag.REQUIRED, EMPTY_MAP)
            .addAuthModuleFactory(() -> new TestServerAuthModule(AuthStatus.SEND_SUCCESS, callCounter, 1), Flag.REQUIRED, EMPTY_MAP)
            .register(authConfigFactory);

        test(AuthStatus.SEND_CONTINUE, 3, registrationId);
    }

    /**
     * Where a ServerAuthModule returns SEND_FAILURE that will end the calls and SEND_FAILURE will be returned.
     */
    @Test
    public void testSendFailure() throws Exception {
        final String registrationId = JaspiConfigurationBuilder.builder(LAYER, APP_CONTEXT)
            .setDescription(DESCRIPTION)
            .addAuthModuleFactory(() -> new TestServerAuthModule(AuthStatus.SEND_SUCCESS, callCounter, -1), Flag.REQUIRED, EMPTY_MAP)
            .addAuthModuleFactory(() -> new TestServerAuthModule(AuthStatus.SEND_FAILURE, callCounter, 2), Flag.REQUIRED, EMPTY_MAP)
            .addAuthModuleFactory(() -> new TestServerAuthModule(AuthStatus.SEND_SUCCESS, callCounter, 1), Flag.REQUIRED, EMPTY_MAP)
            .register(authConfigFactory);

        test(AuthStatus.SEND_FAILURE, 2, registrationId);
    }

    /**
     * Where a ServerAuthModule throws an AuthException that will end the calls and the AuthException will propagate out.
     */
    @Test
    public void testAuthException() throws Exception {
        final String registrationId = JaspiConfigurationBuilder.builder(LAYER, APP_CONTEXT)
            .setDescription(DESCRIPTION)
            .addAuthModuleFactory(() -> new TestServerAuthModule(AuthStatus.SEND_SUCCESS, callCounter, -1), Flag.REQUIRED, EMPTY_MAP)
            .addAuthModuleFactory(() -> new TestServerAuthModule(null, callCounter, 2), Flag.REQUIRED, EMPTY_MAP)
            .addAuthModuleFactory(() -> new TestServerAuthModule(AuthStatus.SEND_SUCCESS, callCounter, 1), Flag.REQUIRED, EMPTY_MAP)
            .register(authConfigFactory);

        test(null, 2, registrationId);
    }

    private void test(final AuthStatus expectedStatus, final int expectedCallCount, final String registrationId) throws Exception {
        test(false, expectedStatus, expectedCallCount, registrationId);
    }
}
