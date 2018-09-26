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

import javax.security.auth.message.AuthStatus;

import org.junit.Test;

/**
 * Testing interaction between ServerAuthModules with different results and different flags.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class AuthModuleValidateTest extends AuthModuleBase {

    /**
     * Test two ServerAuthModules each with a Flag of Required and each returning SUCCESS.
     */
    @Test
    public void testRequired_Success() throws Exception {
        final String registrationId = JaspiConfigurationBuilder.builder(LAYER, APP_CONTEXT)
            .setDescription(DESCRIPTION)
            .addAuthModuleFactory(() -> new TestServerAuthModule(AuthStatus.SUCCESS, callCounter, 1), Flag.REQUIRED, EMPTY_MAP)
            .addAuthModuleFactory(() -> new TestServerAuthModule(AuthStatus.SUCCESS, callCounter, 2), Flag.REQUIRED, EMPTY_MAP)
            .register(authConfigFactory);

        test(AuthStatus.SUCCESS, 2, registrationId);
    }

    /**
     * Test that is an AuthException is thrown from a Required ServerAuthModule it propagates immediately.
     */
    @Test
    public void testRequired_AuthException() throws Exception {
        final String registrationId = JaspiConfigurationBuilder.builder(LAYER, APP_CONTEXT)
            .setDescription(DESCRIPTION)
            .addAuthModuleFactory(() -> new TestServerAuthModule(null, callCounter, 1), Flag.REQUIRED, EMPTY_MAP)
            .addAuthModuleFactory(() -> new TestServerAuthModule(AuthStatus.SUCCESS, callCounter, -1), Flag.REQUIRED, EMPTY_MAP)
            .register(authConfigFactory);

        test(null, 1, registrationId);
    }

    /**
     * Test two ServerAuthModules each with a Flag of Required the first returning SEND_FAILURE and the second returning SUCCESS.
     *
     * Both should be called but the outcome should be SEND_FAILURE.
     */
    @Test
    public void testRequired_Send_Failure() throws Exception {
        final String registrationId = JaspiConfigurationBuilder.builder(LAYER, APP_CONTEXT)
            .setDescription(DESCRIPTION)
            .addAuthModuleFactory(() -> new TestServerAuthModule(AuthStatus.SEND_FAILURE, callCounter, 1), Flag.REQUIRED, EMPTY_MAP)
            .addAuthModuleFactory(() -> new TestServerAuthModule(AuthStatus.SUCCESS, callCounter, 2), Flag.REQUIRED, EMPTY_MAP)
            .register(authConfigFactory);

        test(AuthStatus.SEND_FAILURE, 2, registrationId);
    }

    /**
     * Test two ServerAuthModules each with a Flag of Requisite and each returning SUCCESS.
     */
    @Test
    public void testRequisite_Success() throws Exception {
        final String registrationId = JaspiConfigurationBuilder.builder(LAYER, APP_CONTEXT)
            .setDescription(DESCRIPTION)
            .addAuthModuleFactory(() -> new TestServerAuthModule(AuthStatus.SUCCESS, callCounter, 1), Flag.REQUISITE, EMPTY_MAP)
            .addAuthModuleFactory(() -> new TestServerAuthModule(AuthStatus.SUCCESS, callCounter, 2), Flag.REQUISITE, EMPTY_MAP)
            .register(authConfigFactory);

        test(AuthStatus.SUCCESS, 2, registrationId);
    }

    /**
     * Test that is an AuthException is thrown from a Requisite ServerAuthModule it propagates immediately.
     */
    @Test
    public void testRequisite_AuthException() throws Exception {
        final String registrationId = JaspiConfigurationBuilder.builder(LAYER, APP_CONTEXT)
            .setDescription(DESCRIPTION)
            .addAuthModuleFactory(() -> new TestServerAuthModule(null, callCounter, 1), Flag.REQUISITE, EMPTY_MAP)
            .addAuthModuleFactory(() -> new TestServerAuthModule(AuthStatus.SUCCESS, callCounter, -1), Flag.REQUIRED, EMPTY_MAP)
            .register(authConfigFactory);

        test(null, 1, registrationId);
    }

    /**
     * Test two ServerAuthModules each with a Flag of Requisite the first returning SEND_FAILURE and the second returning SUCCESS.
     *
     * Only the first should be called and the outcome should be SEND_FAILURE.
     */
    @Test
    public void testRequisite_Send_Failure() throws Exception {
        final String registrationId = JaspiConfigurationBuilder.builder(LAYER, APP_CONTEXT)
            .setDescription(DESCRIPTION)
            .addAuthModuleFactory(() -> new TestServerAuthModule(AuthStatus.SEND_FAILURE, callCounter, 1), Flag.REQUISITE, EMPTY_MAP)
            .addAuthModuleFactory(() -> new TestServerAuthModule(AuthStatus.SUCCESS, callCounter, -1), Flag.REQUISITE, EMPTY_MAP)
            .register(authConfigFactory);

        test(AuthStatus.SEND_FAILURE, 1, registrationId);
    }

    /**
     * Test three ServerAuthModules the first and last being Required and the middle one Sufficient, all return Success.
     *
     * As a Sufficient SAM returns SUCCESS no further modules should be called.
     */
    @Test
    public void testSufficient_Success() throws Exception {
        final String registrationId = JaspiConfigurationBuilder.builder(LAYER, APP_CONTEXT)
            .setDescription(DESCRIPTION)
            .addAuthModuleFactory(() -> new TestServerAuthModule(AuthStatus.SUCCESS, callCounter, 1), Flag.REQUIRED, EMPTY_MAP)
            .addAuthModuleFactory(() -> new TestServerAuthModule(AuthStatus.SUCCESS, callCounter, 2), Flag.SUFFICIENT, EMPTY_MAP)
            .addAuthModuleFactory(() -> new TestServerAuthModule(AuthStatus.SUCCESS, callCounter, -1), Flag.REQUIRED, EMPTY_MAP)
            .register(authConfigFactory);

        test(AuthStatus.SUCCESS, 2, registrationId);
    }

    /**
     * Test that is an AuthException is thrown from a Sufficient ServerAuthModule it propagates immediately.
     */
    @Test
    public void testSufficient_AuthException() throws Exception {
        final String registrationId = JaspiConfigurationBuilder.builder(LAYER, APP_CONTEXT)
            .setDescription(DESCRIPTION)
            .addAuthModuleFactory(() -> new TestServerAuthModule(null, callCounter, 1), Flag.SUFFICIENT, EMPTY_MAP)
            .addAuthModuleFactory(() -> new TestServerAuthModule(AuthStatus.SUCCESS, callCounter, -1), Flag.REQUIRED, EMPTY_MAP)
            .register(authConfigFactory);

        test(null, 1, registrationId);
    }

    /**
     * The failure of the Sufficient ServerAuthModule is ignored as there are Required SAMs also defined.
     */
    @Test
    public void testSufficient_Send_Failure_Ignored() throws Exception {
        final String registrationId = JaspiConfigurationBuilder.builder(LAYER, APP_CONTEXT)
            .setDescription(DESCRIPTION)
            .addAuthModuleFactory(() -> new TestServerAuthModule(AuthStatus.SUCCESS, callCounter, 1), Flag.REQUIRED, EMPTY_MAP)
            .addAuthModuleFactory(() -> new TestServerAuthModule(AuthStatus.SEND_FAILURE, callCounter, 2), Flag.SUFFICIENT, EMPTY_MAP)
            .addAuthModuleFactory(() -> new TestServerAuthModule(AuthStatus.SUCCESS, callCounter, 3), Flag.REQUIRED, EMPTY_MAP)
            .register(authConfigFactory);

        test(AuthStatus.SUCCESS, 3, registrationId);
    }

    /**
     * A Sufficient ServerAuthModule on it's own will affect the outcome.
     */
    @Test
    public void testSufficient_Send_Failure() throws Exception {
        final String registrationId = JaspiConfigurationBuilder.builder(LAYER, APP_CONTEXT)
            .setDescription(DESCRIPTION)
            .addAuthModuleFactory(() -> new TestServerAuthModule(AuthStatus.SEND_FAILURE, callCounter, 1), Flag.SUFFICIENT, EMPTY_MAP)
            .register(authConfigFactory);

        test(AuthStatus.SEND_FAILURE, 1, registrationId);
    }

    /**
     * The Success from the Optional ServerAuthModule is ignored as there is a subsequent Required SAM.
     */
    @Test
    public void testOptional_Success_Ignored() throws Exception {
        final String registrationId = JaspiConfigurationBuilder.builder(LAYER, APP_CONTEXT)
            .setDescription(DESCRIPTION)
            .addAuthModuleFactory(() -> new TestServerAuthModule(AuthStatus.SUCCESS, callCounter, 1), Flag.OPTIONAL, EMPTY_MAP)
            .addAuthModuleFactory(() -> new TestServerAuthModule(AuthStatus.SEND_FAILURE, callCounter, 2), Flag.REQUIRED, EMPTY_MAP)
            .register(authConfigFactory);

        test(AuthStatus.SEND_FAILURE, 2, registrationId);
    }

    /**
     * The failure from the Optional ServerAuthModule is ignored as there is a subsequent Required SAM.
     */
    @Test
    public void testOptional_Send_Failure_Ignored() throws Exception {
        final String registrationId = JaspiConfigurationBuilder.builder(LAYER, APP_CONTEXT)
            .setDescription(DESCRIPTION)
            .addAuthModuleFactory(() -> new TestServerAuthModule(AuthStatus.SEND_FAILURE, callCounter, 1), Flag.OPTIONAL, EMPTY_MAP)
            .addAuthModuleFactory(() -> new TestServerAuthModule(AuthStatus.SUCCESS, callCounter, 2), Flag.REQUIRED, EMPTY_MAP)
            .register(authConfigFactory);

        test(AuthStatus.SUCCESS, 2, registrationId);
    }

    /**
     * On it's own the Success of an Optional ServerAuthModule is returned.
     */
    @Test
    public void testOptional_Success() throws Exception {
        final String registrationId = JaspiConfigurationBuilder.builder(LAYER, APP_CONTEXT)
            .setDescription(DESCRIPTION)
            .addAuthModuleFactory(() -> new TestServerAuthModule(AuthStatus.SUCCESS, callCounter, 1), Flag.OPTIONAL, EMPTY_MAP)
            .register(authConfigFactory);

        test(AuthStatus.SUCCESS, 1, registrationId);
    }

    /**
     * On it's own the Failure of an Optional ServerAuthModule is returned.
     */
    @Test
    public void testOptional_Send_Failure() throws Exception {
        final String registrationId = JaspiConfigurationBuilder.builder(LAYER, APP_CONTEXT)
            .setDescription(DESCRIPTION)
            .addAuthModuleFactory(() -> new TestServerAuthModule(AuthStatus.SEND_FAILURE, callCounter, 1), Flag.OPTIONAL, EMPTY_MAP)
            .register(authConfigFactory);

        test(AuthStatus.SEND_FAILURE, 1, registrationId);
    }

    /**
     * For two optional ServerAuthModules returning different results the most successful result is returned.
     */
    @Test
    public void testOptional_Mixed() throws Exception {
        final String registrationId = JaspiConfigurationBuilder.builder(LAYER, APP_CONTEXT)
            .setDescription(DESCRIPTION)
            .addAuthModuleFactory(() -> new TestServerAuthModule(AuthStatus.SEND_CONTINUE, callCounter, 1), Flag.OPTIONAL, EMPTY_MAP)
            .addAuthModuleFactory(() -> new TestServerAuthModule(AuthStatus.SEND_FAILURE, callCounter, 2), Flag.OPTIONAL, EMPTY_MAP)
            .register(authConfigFactory);

        test(AuthStatus.SEND_CONTINUE, 2, registrationId);
    }

    /**
     * Test that is an AuthException is thrown from a Sufficient ServerAuthModule it propagates immediately.
     */
    @Test
    public void testOptional_AuthException() throws Exception {
        final String registrationId = JaspiConfigurationBuilder.builder(LAYER, APP_CONTEXT)
            .setDescription(DESCRIPTION)
            .addAuthModuleFactory(() -> new TestServerAuthModule(null, callCounter, 1), Flag.OPTIONAL, EMPTY_MAP)
            .addAuthModuleFactory(() -> new TestServerAuthModule(AuthStatus.SUCCESS, callCounter, -1), Flag.REQUIRED, EMPTY_MAP)
            .register(authConfigFactory);

        test(null, 1, registrationId);
    }

    private void test(final AuthStatus expectedStatus, final int expectedCallCount, final String registrationId) throws Exception {
        test(true, expectedStatus, expectedCallCount, registrationId);
    }
}
