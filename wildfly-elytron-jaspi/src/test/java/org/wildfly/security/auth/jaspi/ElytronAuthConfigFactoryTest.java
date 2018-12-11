/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.jaspi;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Collections;

import javax.security.auth.message.config.AuthConfigFactory;
import javax.security.auth.message.config.AuthConfigFactory.RegistrationContext;
import javax.security.auth.message.config.RegistrationListener;

import org.junit.Test;

/**
 * A test case for the {@link ElytronAuthConfigFactory}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class ElytronAuthConfigFactoryTest {

    private static final String APP_CONTEXT = "application-context";
    private static final String LAYER = "layer";
    private static final String DESCRIPTION = "test description";
    private final AuthConfigFactory authConfigFactory = new ElytronAuthConfigFactory();

    @Test
    public void testRegisterInstance() {
        assertNull("Existing Registration", authConfigFactory.getConfigProvider(LAYER, APP_CONTEXT, null));
        final String registrationId = authConfigFactory.registerConfigProvider(new TestAuthConfigProvider("testRegisterInstance"), LAYER, APP_CONTEXT, DESCRIPTION);
        assertNotNull("Have a registration ID", registrationId);
        RegistrationContext registrationContext = authConfigFactory.getRegistrationContext(registrationId);
        assertEquals("Incorrect application context.", APP_CONTEXT, registrationContext.getAppContext());
        assertEquals("Incorrect layer.", LAYER, registrationContext.getMessageLayer());
        assertEquals("Incorrect description.", DESCRIPTION, registrationContext.getDescription());
        assertEquals("Incorrect AuthConfigProvider", "testRegisterInstance", ((TestAuthConfigProvider) authConfigFactory.getConfigProvider(LAYER, APP_CONTEXT, null)).getId());
        authConfigFactory.removeRegistration(registrationId);
        assertNull("Removed Registration", authConfigFactory.getConfigProvider(LAYER, APP_CONTEXT, null));
    }

    @Test
    public void testRegisterClassName() {
        assertNull("Existing Registration", authConfigFactory.getConfigProvider(LAYER, APP_CONTEXT, null));
        final String registrationId = authConfigFactory.registerConfigProvider(TestAuthConfigProvider.class.getName(), Collections.emptyMap(), LAYER, APP_CONTEXT, DESCRIPTION);
        assertNotNull("Have a registration ID", registrationId);
        RegistrationContext registrationContext = authConfigFactory.getRegistrationContext(registrationId);
        assertEquals("Incorrect application context.", APP_CONTEXT, registrationContext.getAppContext());
        assertEquals("Incorrect layer.", LAYER, registrationContext.getMessageLayer());
        assertEquals("Incorrect description.", DESCRIPTION, registrationContext.getDescription());
        assertEquals("Incorrect AuthConfigProvider", TestAuthConfigProvider.DEFAULT, ((TestAuthConfigProvider) authConfigFactory.getConfigProvider(LAYER, APP_CONTEXT, null)).getId());
        authConfigFactory.removeRegistration(registrationId);
        assertNull("Removed Registration", authConfigFactory.getConfigProvider(LAYER, APP_CONTEXT, null));
    }

    @Test
    public void testRegistrationNotification_Full() {
        final TestRegistrationListener registrationListener = new TestRegistrationListener();

        String registrationId = null;
        assertNull("Existing Registration", authConfigFactory.getConfigProvider(LAYER, APP_CONTEXT, registrationListener));
        registrationId = authConfigFactory.registerConfigProvider(new TestAuthConfigProvider("One"), LAYER, APP_CONTEXT, DESCRIPTION);
        assertRegistrationListenerCalled(registrationListener, APP_CONTEXT, LAYER); // Notification for new registration
        assertEquals("Incorrect AuthConfigProvider", "One", ((TestAuthConfigProvider) authConfigFactory.getConfigProvider(LAYER, APP_CONTEXT, null)).getId());
        registrationId = authConfigFactory.registerConfigProvider(new TestAuthConfigProvider("Two"), LAYER, APP_CONTEXT, DESCRIPTION);
        assertFalse("Unexpected notification", registrationListener.isNotified());  // Once notified a listener is removed.
        assertEquals("Incorrect AuthConfigProvider", "Two", ((TestAuthConfigProvider) authConfigFactory.getConfigProvider(LAYER, APP_CONTEXT, registrationListener)).getId());
        registrationId = authConfigFactory.registerConfigProvider(new TestAuthConfigProvider("Three"), LAYER, APP_CONTEXT, DESCRIPTION);
        assertRegistrationListenerCalled(registrationListener, APP_CONTEXT, LAYER); // Notification for replacement registration
        assertEquals("Incorrect AuthConfigProvider", "Three", ((TestAuthConfigProvider) authConfigFactory.getConfigProvider(LAYER, APP_CONTEXT, registrationListener)).getId());
        authConfigFactory.detachListener(registrationListener, LAYER, APP_CONTEXT);
        registrationId = authConfigFactory.registerConfigProvider(new TestAuthConfigProvider("Four"), LAYER, APP_CONTEXT, DESCRIPTION);
        assertFalse("Unexpected notification", registrationListener.isNotified());
        assertEquals("Incorrect AuthConfigProvider", "Four", ((TestAuthConfigProvider) authConfigFactory.getConfigProvider(LAYER, APP_CONTEXT, registrationListener)).getId());
        authConfigFactory.removeRegistration(registrationId);
        assertRegistrationListenerCalled(registrationListener, APP_CONTEXT, LAYER); // Notification for removal
    }

    @Test
    public void testRegistrationNotification_AppContext() {
        final TestRegistrationListener registrationListener = new TestRegistrationListener();

        String registrationId = null;
        assertNull("Existing Registration", authConfigFactory.getConfigProvider(null, APP_CONTEXT, registrationListener));
        registrationId = authConfigFactory.registerConfigProvider(new TestAuthConfigProvider("One"), null, APP_CONTEXT, DESCRIPTION);
        assertRegistrationListenerCalled(registrationListener, APP_CONTEXT, null); // Notification for new registration
        assertEquals("Incorrect AuthConfigProvider", "One", ((TestAuthConfigProvider) authConfigFactory.getConfigProvider(null, APP_CONTEXT, null)).getId());
        registrationId = authConfigFactory.registerConfigProvider(new TestAuthConfigProvider("Two"), null, APP_CONTEXT, DESCRIPTION);
        assertFalse("Unexpected notification", registrationListener.isNotified());  // Once notified a listener is removed.
        assertEquals("Incorrect AuthConfigProvider", "Two", ((TestAuthConfigProvider) authConfigFactory.getConfigProvider(null, APP_CONTEXT, registrationListener)).getId());
        registrationId = authConfigFactory.registerConfigProvider(new TestAuthConfigProvider("Three"), null, APP_CONTEXT, DESCRIPTION);
        assertRegistrationListenerCalled(registrationListener, APP_CONTEXT, null); // Notification for replacement registration
        assertEquals("Incorrect AuthConfigProvider", "Three", ((TestAuthConfigProvider) authConfigFactory.getConfigProvider(null, APP_CONTEXT, registrationListener)).getId());
        authConfigFactory.detachListener(registrationListener, null, APP_CONTEXT);
        registrationId = authConfigFactory.registerConfigProvider(new TestAuthConfigProvider("Four"), null, APP_CONTEXT, DESCRIPTION);
        assertFalse("Unexpected notification", registrationListener.isNotified());
        assertEquals("Incorrect AuthConfigProvider", "Four", ((TestAuthConfigProvider) authConfigFactory.getConfigProvider(null, APP_CONTEXT, registrationListener)).getId());
        authConfigFactory.removeRegistration(registrationId);
        assertRegistrationListenerCalled(registrationListener, APP_CONTEXT, null); // Notification for removal
    }

    @Test
    public void testRegistrationNotification_Layer() {
        final TestRegistrationListener registrationListener = new TestRegistrationListener();

        String registrationId = null;
        assertNull("Existing Registration", authConfigFactory.getConfigProvider(LAYER, null, registrationListener));
        registrationId = authConfigFactory.registerConfigProvider(new TestAuthConfigProvider("One"), LAYER, null, DESCRIPTION);
        assertRegistrationListenerCalled(registrationListener, null, LAYER); // Notification for new registration
        assertEquals("Incorrect AuthConfigProvider", "One", ((TestAuthConfigProvider) authConfigFactory.getConfigProvider(LAYER, null, null)).getId());
        registrationId = authConfigFactory.registerConfigProvider(new TestAuthConfigProvider("Two"), LAYER, null, DESCRIPTION);
        assertFalse("Unexpected notification", registrationListener.isNotified());  // Once notified a listener is removed.
        assertEquals("Incorrect AuthConfigProvider", "Two", ((TestAuthConfigProvider) authConfigFactory.getConfigProvider(LAYER, null, registrationListener)).getId());
        registrationId = authConfigFactory.registerConfigProvider(new TestAuthConfigProvider("Three"), LAYER, null, DESCRIPTION);
        assertRegistrationListenerCalled(registrationListener, null, LAYER); // Notification for replacement registration
        assertEquals("Incorrect AuthConfigProvider", "Three", ((TestAuthConfigProvider) authConfigFactory.getConfigProvider(LAYER, null, registrationListener)).getId());
        authConfigFactory.detachListener(registrationListener, LAYER, null);
        registrationId = authConfigFactory.registerConfigProvider(new TestAuthConfigProvider("Four"), LAYER, null, DESCRIPTION);
        assertFalse("Unexpected notification", registrationListener.isNotified());
        assertEquals("Incorrect AuthConfigProvider", "Four", ((TestAuthConfigProvider) authConfigFactory.getConfigProvider(LAYER, null, registrationListener)).getId());
        authConfigFactory.removeRegistration(registrationId);
        assertRegistrationListenerCalled(registrationListener, null, LAYER); // Notification for removal
    }

    @Test
    public void testRegistrationNotification_Default() {
        final TestRegistrationListener registrationListener = new TestRegistrationListener();

        String registrationId = null;
        assertNull("Existing Registration", authConfigFactory.getConfigProvider(null, null, registrationListener));
        registrationId = authConfigFactory.registerConfigProvider(new TestAuthConfigProvider("One"), null, null, DESCRIPTION);
        assertRegistrationListenerCalled(registrationListener, null, null); // Notification for new registration
        assertEquals("Incorrect AuthConfigProvider", "One", ((TestAuthConfigProvider) authConfigFactory.getConfigProvider(null, null, null)).getId());
        registrationId = authConfigFactory.registerConfigProvider(new TestAuthConfigProvider("Two"), null, null, DESCRIPTION);
        assertFalse("Unexpected notification", registrationListener.isNotified());  // Once notified a listener is removed.
        assertEquals("Incorrect AuthConfigProvider", "Two", ((TestAuthConfigProvider) authConfigFactory.getConfigProvider(null, null, registrationListener)).getId());
        registrationId = authConfigFactory.registerConfigProvider(new TestAuthConfigProvider("Three"), null, null, DESCRIPTION);
        assertRegistrationListenerCalled(registrationListener, null, null); // Notification for replacement registration
        assertEquals("Incorrect AuthConfigProvider", "Three", ((TestAuthConfigProvider) authConfigFactory.getConfigProvider(LAYER, null, registrationListener)).getId());
        authConfigFactory.detachListener(registrationListener, null, null);
        registrationId = authConfigFactory.registerConfigProvider(new TestAuthConfigProvider("Four"), null, null, DESCRIPTION);
        assertFalse("Unexpected notification", registrationListener.isNotified());
        assertEquals("Incorrect AuthConfigProvider", "Four", ((TestAuthConfigProvider) authConfigFactory.getConfigProvider(null, null, registrationListener)).getId());
        authConfigFactory.removeRegistration(registrationId);
        assertRegistrationListenerCalled(registrationListener, null, null); // Notification for removal
    }

    @Test
    public void testGetConfigProvider() {
        // getConfigProvider at runtime will always be passed an appContext and layer.

        assertNull("Existing Registration", authConfigFactory.getConfigProvider(LAYER, APP_CONTEXT, null));

        String fullId = authConfigFactory.registerConfigProvider(new TestAuthConfigProvider("One"), LAYER, APP_CONTEXT, DESCRIPTION);
        // These next two are deliberately in the opposite order as registration can happen out of order.
        String layerId = authConfigFactory.registerConfigProvider(new TestAuthConfigProvider("Two"), LAYER, null, DESCRIPTION);
        String appContextId = authConfigFactory.registerConfigProvider(new TestAuthConfigProvider("Three"), null, APP_CONTEXT, DESCRIPTION);
        String defaultId = authConfigFactory.registerConfigProvider(new TestAuthConfigProvider("Four"), null, null, DESCRIPTION);

        assertEquals("Incorrect AuthConfigProvider", "One", ((TestAuthConfigProvider) authConfigFactory.getConfigProvider(LAYER, APP_CONTEXT, null)).getId());
        authConfigFactory.removeRegistration(fullId);
        assertEquals("Incorrect AuthConfigProvider", "Three", ((TestAuthConfigProvider) authConfigFactory.getConfigProvider(LAYER, APP_CONTEXT, null)).getId());
        authConfigFactory.removeRegistration(appContextId);
        assertEquals("Incorrect AuthConfigProvider", "Two", ((TestAuthConfigProvider) authConfigFactory.getConfigProvider(LAYER, APP_CONTEXT, null)).getId());
        authConfigFactory.removeRegistration(layerId);
        assertEquals("Incorrect AuthConfigProvider", "Four", ((TestAuthConfigProvider) authConfigFactory.getConfigProvider(LAYER, APP_CONTEXT, null)).getId());
        authConfigFactory.removeRegistration(defaultId);

        assertNull("Existing Registration", authConfigFactory.getConfigProvider(LAYER, APP_CONTEXT, null));
    }

    private void assertRegistrationListenerCalled(final TestRegistrationListener registrationListener, final String appContext, final String layer) {
        assertTrue("Notification not recieved", registrationListener.isNotified());
        assertEquals("Unexpected appContext", appContext, registrationListener.getAppContext());
        assertEquals("Unexpected layer", layer, registrationListener.getLayer());
        registrationListener.reset();
    }

    static class TestRegistrationListener implements RegistrationListener {

        private boolean notified = false;
        private String layer = null;
        private String appContext = null;

        @Override
        public void notify(String layer, String appContext) {
            notified = true;
            this.layer = layer;
            this.appContext = appContext;
        }

        boolean isNotified() {
            return notified;
        }

        String getLayer() {
            return layer;
        }

        String getAppContext() {
            return appContext;
        }

        void reset() {
            notified = false;
            layer = null;
            appContext = null;
        }

    }

}
