/*
 * Copyright 2020 Red Hat, Inc.
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

package org.wildfly.security.manager;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.net.URL;
import java.security.AccessControlException;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.Permission;
import java.security.Permissions;
import java.security.PrivilegedAction;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.PropertyPermission;
import java.util.Stack;

import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.wildfly.security.ParametricPrivilegedAction;
import org.wildfly.security.manager.action.ReadPropertyAction;

/**
 * Test case to verify calls via the {@link WildFlySecurityManager} are not incorrectly intercepted when an alternative
 * {@link SecurityManager} is installed.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class AlternateSecurityManagerTest {

    private static final String KEY = "test-key";
    private static final String VALUE = "test-key";

    private static final Permission INTERESTING_PERMISSION = new PropertyPermission(KEY, "read");

    private final CustomSecurityManager securityManager = new CustomSecurityManager();

    private volatile AccessControlContext context;

    /*
     * Used to verify we are the final CodeSource in calls and the WildFlySecurityManager is not added.
     */
    private volatile URL ourCodeSource;
    private volatile URL actionCodeSource;
    private volatile URL managerCodeSource;

    @Before
    public void before() {
        Assume.assumeTrue("Skipping AlternateSecurityManagerTest suite, tests are not being run on JDK 17 or lower.",
                Integer.parseInt(System.getProperty("java.specification.version")) <= 17);
        context = new AccessControlContext(new ProtectionDomain[] { new ProtectionDomain(null, new Permissions()) });
        ourCodeSource = AlternateSecurityManagerTest.class.getProtectionDomain().getCodeSource().getLocation();
        actionCodeSource = ReadPropertyAction.class.getProtectionDomain().getCodeSource().getLocation();
        managerCodeSource = WildFlySecurityManager.class.getProtectionDomain().getCodeSource().getLocation();

        System.setProperty(KEY, VALUE);
        System.setSecurityManager(securityManager);
        securityManager.reset();
    }

    @After
    public void removeSecurityManager() {
        System.setSecurityManager(null);
        System.clearProperty(KEY);
        securityManager.reset();

        context = null;
        actionCodeSource = null;
        managerCodeSource = null;
    }

    @Test
    public void testGetProperty() {
        String value = System.getProperty(KEY);
        assertEquals("Retrieved property", VALUE,  value);

        List<Class<?>[]> baseDomains = securityManager.reset();
        assertEquals("Expected checkPermission Calls", 1, baseDomains.size());
        assertRelevantCodeSources(baseDomains.get(0), ourCodeSource);
        assertFalse("WildFlySecurityManager should not be on the direct stack", containsClass(baseDomains.get(0), WildFlySecurityManager.class));
    }

    @Test
    public void testGetPropertyAction() {
        String value = AccessController.doPrivileged(new CustomAction());
        assertEquals("Retrieved property", VALUE,  value);

        List<Class<?>[]> baseDomains = securityManager.reset();
        assertEquals("Expected checkPermission Calls", 1, baseDomains.size());
        assertRelevantCodeSources(baseDomains.get(0), ourCodeSource);
        assertFalse("WildFlySecurityManager should not be on the direct stack", containsClass(baseDomains.get(0), WildFlySecurityManager.class));
    }

    @Test
    public void testGetPropertyPrivileged() {
        assertEquals("Retrieved property", VALUE,  WildFlySecurityManager.getPropertyPrivileged(KEY, null));

        List<Class<?>[]> baseDomains = securityManager.reset();
        assertEquals("Expected checkPermission Calls", 1, baseDomains.size());
        assertRelevantCodeSources(baseDomains.get(0), ourCodeSource, actionCodeSource, managerCodeSource);
        assertTrue("WildFlySecurityManager should be on the privileged stack", containsClass(baseDomains.get(0), WildFlySecurityManager.class));
    }

    @Test
    public void testDoUnchecked() {
        /*
         * doUnchecked is the equivalent of a call to doPrivileged.
         */

        String value = AccessController.doPrivileged(new CustomAction());
        assertEquals("Retrieved property", VALUE,  value);

        List<Class<?>[]> baseDomains = securityManager.reset();
        assertEquals("Expected checkPermission Calls", 1, baseDomains.size());
        assertRelevantCodeSources(baseDomains.get(0), ourCodeSource);

        value = WildFlySecurityManager.doUnchecked(new CustomAction());
        assertEquals("Retrieved property", VALUE,  value);

        List<Class<?>[]> actualDomains = securityManager.reset();
        assertEquals("Expected checkPermission Calls", 1, actualDomains.size());
        assertRelevantCodeSources(actualDomains.get(0), ourCodeSource, managerCodeSource);
        assertTrue("WildFlySecurityManager should be on the privileged stack", containsClass(actualDomains.get(0), WildFlySecurityManager.class));
    }

    @Test
    public void testDoUnchecked_WithContext() {
        assertPropertyReadDenied(new PrivilegedAction<String>() {
            @Override
            public String run() {
                return AccessController.doPrivileged(new CustomAction(), context);
            }
        });

        List<Class<?>[]> baseDomains = securityManager.reset();
        assertEquals("Expected checkPermission Calls", 1, baseDomains.size());
        assertRelevantCodeSources(baseDomains.get(0), ourCodeSource);

        assertPropertyReadDenied(new PrivilegedAction<String>() {
            @Override
            public String run() {
                return WildFlySecurityManager.doUnchecked(new CustomAction(), context);
            }
        });

        List<Class<?>[]> actualDomains = securityManager.reset();
        assertEquals("Expected checkPermission Calls", 1, actualDomains.size());
        assertRelevantCodeSources(actualDomains.get(0), ourCodeSource, managerCodeSource);
        assertTrue("WildFlySecurityManager should be on the privileged stack", containsClass(actualDomains.get(0), WildFlySecurityManager.class));

        assertPropertyReadDenied(new PrivilegedAction<String>() {
            @Override
            public String run() {
                return WildFlySecurityManager.doUnchecked(KEY, new CustomAction(), context);
            }
        });

        List<Class<?>[]> parameterDomains = securityManager.reset();
        assertEquals("Expected checkPermission Calls", 1, parameterDomains.size());
        assertRelevantCodeSources(parameterDomains.get(0), ourCodeSource, managerCodeSource);
    }

    @Test
    public void testDoChecked() {
        String value = WildFlySecurityManager.doChecked(new CustomAction());
        assertEquals("Retrieved property", VALUE,  value);

        List<Class<?>[]> baseDomains = securityManager.reset();
        assertEquals("Expected checkPermission Calls", 1, baseDomains.size());
        assertTrue("WildFlySecurityManager should be on the checked stack", containsClass(baseDomains.get(0), WildFlySecurityManager.class));

        value = WildFlySecurityManager.doChecked(KEY, new CustomAction());
        assertEquals("Retrieved property", VALUE,  value);

        List<Class<?>[]> actualDomains = securityManager.reset();
        assertEquals("Expected checkPermission Calls", 1, actualDomains.size());
        assertEquals("Matching relevant code sources", getRelevantCodeSources(baseDomains.get(0)), getRelevantCodeSources(actualDomains.get(0)));
    }

    @Test
    public void testDoChecked_WithContext() {
        assertPropertyReadDenied(new PrivilegedAction<String>() {
            @Override
            public String run() {
                return WildFlySecurityManager.doChecked(new CustomAction(), context);
            }
        });

        List<Class<?>[]> baseDomains = securityManager.reset();
        assertEquals("Expected checkPermission Calls", 1, baseDomains.size());
        assertRelevantCodeSources(baseDomains.get(0), ourCodeSource, managerCodeSource);

        assertPropertyReadDenied(new PrivilegedAction<String>() {
            @Override
            public String run() {
                return WildFlySecurityManager.doChecked(KEY, new CustomAction(), context);
            }
        });

        List<Class<?>[]> actualDomains = securityManager.reset();
        assertEquals("Expected checkPermission Calls", 1, actualDomains.size());
        assertEquals("Matching relevant code sources", getRelevantCodeSources(baseDomains.get(0)), getRelevantCodeSources(actualDomains.get(0)));
    }

    @Test
    public void testDoPrivilegedWithParameter() {
        String value = AccessController.doPrivileged(new CustomAction());
        assertEquals("Retrieved property", VALUE,  value);

        List<Class<?>[]> baseDomains = securityManager.reset();
        assertEquals("Expected checkPermission Calls", 1, baseDomains.size());
        assertRelevantCodeSources(baseDomains.get(0), ourCodeSource);

        value = WildFlySecurityManager.doPrivilegedWithParameter(KEY, new CustomAction());
        assertEquals("Retrieved property", VALUE,  value);

        List<Class<?>[]> actualDomains = securityManager.reset();
        assertEquals("Expected checkPermission Calls", 1, actualDomains.size());
        assertRelevantCodeSources(actualDomains.get(0), ourCodeSource, managerCodeSource);
        assertTrue("WildFlySecurityManager should be on the privileged stack", containsClass(actualDomains.get(0), WildFlySecurityManager.class));
    }

    @Test
    public void testDoPrivilegedWithParameter_WithContext() {
        assertPropertyReadDenied(new PrivilegedAction<String>() {
            @Override
            public String run() {
                return AccessController.doPrivileged(new CustomAction(), context);
            }
        });

        List<Class<?>[]> baseDomains = securityManager.reset();
        assertEquals("Expected checkPermission Calls", 1, baseDomains.size());
        assertRelevantCodeSources(baseDomains.get(0), ourCodeSource);

        assertPropertyReadDenied(new PrivilegedAction<String>() {
            @Override
            public String run() {
                return WildFlySecurityManager.doPrivilegedWithParameter(KEY, new CustomAction(), context);
            }
        });

        List<Class<?>[]> actualDomains = securityManager.reset();
        assertEquals("Expected checkPermission Calls", 1, actualDomains.size());
        assertRelevantCodeSources(actualDomains.get(0), ourCodeSource, managerCodeSource);
    }

    private void assertPropertyReadDenied(final PrivilegedAction<String> action) {
        securityManager.setEnforceSecurityContext(true);
        try {
            action.run();
            fail("Expected property read to be denied");
        } catch (AccessControlException expected) {
            // expected
        } finally {
            securityManager.setEnforceSecurityContext(false);
        }
    }

    private void assertRelevantCodeSources(final Class<?>[] context, final URL... expected) {
        final List<URL> actual = getRelevantCodeSources(context);
        int matchIndex = 0;
        for (URL current : actual) {
            if (current.equals(expected[matchIndex])) {
                matchIndex++;
                if (matchIndex == expected.length) {
                    return;
                }
            }
        }
        assertEquals("Expected relevant code sources in order " + Arrays.asList(expected) + " but was " + actual, expected.length, matchIndex);
    }

    private List<URL> getRelevantCodeSources(final Class<?>[] context) {
        ArrayList<URL> urls = new ArrayList<>();
        URL previous = null;
        for (Class<?> currentClass : context) {
            URL current = getCodeSource(currentClass);
            if (current != null && isRelevantCodeSource(current) && ! current.equals(previous)) {
                urls.add(current);
                previous = current;
            }
        }
        return urls;
    }

    private boolean isRelevantCodeSource(final URL url) {
        return url.equals(ourCodeSource) || url.equals(actionCodeSource) || url.equals(managerCodeSource);
    }

    private static URL getCodeSource(final Class<?> clazz) {
        final ProtectionDomain protectionDomain = clazz.getProtectionDomain();
        return protectionDomain != null && protectionDomain.getCodeSource() != null ? protectionDomain.getCodeSource().getLocation() : null;
    }

    private static boolean containsClass(final Class<?>[] context, final Class<?> expectedClass) {
        for (Class<?> current : context) {
            if (current == expectedClass) {
                return true;
            }
        }
        return false;
    }

    static class CustomSecurityManager extends SecurityManager {

        private final Stack<Class<?>[]> calls = new Stack<>();
        private volatile boolean enforceSecurityContext;

        List<Class<?>[]> reset() {
            List<Class<?>[]> response = new ArrayList<>(calls);
            calls.clear();

            return response;
        }

        void setEnforceSecurityContext(final boolean enforceSecurityContext) {
            this.enforceSecurityContext = enforceSecurityContext;
        }

        @Override
        public void checkPermission(Permission permission) {
            if (INTERESTING_PERMISSION.equals(permission)) {
                System.out.println("Permission Check " + permission.toString());
                calls.push(getClassContext());
                if (enforceSecurityContext) {
                    ((AccessControlContext) getSecurityContext()).checkPermission(permission);
                }
            }
        }
    }

    static class CustomAction implements PrivilegedAction<String>, ParametricPrivilegedAction<String, String> {

        @Override
        public String run(String parameter) {
            return System.getProperty(parameter);
        }

        @Override
        public String run() {
            return run(KEY);
        }

    }

}
