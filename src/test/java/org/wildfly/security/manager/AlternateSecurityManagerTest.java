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

import static java.security.AccessController.doPrivileged;
import static org.junit.Assert.assertEquals;

import java.lang.reflect.Field;
import java.net.URL;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.Permission;
import java.security.PrivilegedAction;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.List;
import java.util.PropertyPermission;
import java.util.Stack;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.wildfly.security.ParametricPrivilegedAction;

import sun.misc.Unsafe;

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

    private static final Unsafe unsafe;
    private static final long pdStackOffset;

    static {
        final Field pdField;
        try {
            // does not need to be accessible
            pdField = AccessControlContext.class.getDeclaredField("context");
        } catch (NoSuchFieldException e) {
            throw new NoSuchFieldError(e.getMessage());
        }
        if (pdField.getType() != ProtectionDomain[].class) {
            throw new Error();
        }
        try {
            unsafe = (Unsafe) doPrivileged(new GetAccessibleDeclaredFieldAction(Unsafe.class, "theUnsafe")).get(null);
        } catch (IllegalAccessException e) {
            throw new IllegalAccessError(e.getMessage());
        }
        pdStackOffset = unsafe.objectFieldOffset(pdField);
    }

    private final CustomSecurityManager securityManager = new CustomSecurityManager();

    private volatile AccessControlContext context;

    /*
     * Used to verify we are the final CodeSource in calls and the WildFlySecurityManager is not added.
     */
    private volatile URL ourCodeSource;

    @Before
    public void before() {
        AccessControlContext current = AccessController.getContext();
        ProtectionDomain[] domains = getProtectionDomainStack(current);

        context = new AccessControlContext(new ProtectionDomain[] { domains[1] });
        ourCodeSource = domains[0].getCodeSource().getLocation();

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
    }

    @Test
    public void testGetProperty() {
        String value = System.getProperty(KEY);
        assertEquals("Retrieved property", VALUE,  value);

        List<ProtectionDomain[]> baseDomains = securityManager.reset();
        assertEquals("Expected checkPermission Calls", 1, baseDomains.size());

        /*
         * We can not check the number of ProtectionDomains here as the method of calling the test
         * could influence the stack.
         */

        assertEquals("Our CodeSource", ourCodeSource, baseDomains.get(0)[0].getCodeSource().getLocation());
    }

    @Test
    public void testGetPropertyAction() {
        String value = AccessController.doPrivileged(new CustomAction());
        assertEquals("Retrieved property", VALUE,  value);

        List<ProtectionDomain[]> baseDomains = securityManager.reset();
        assertEquals("Expected checkPermission Calls", 1, baseDomains.size());

        ProtectionDomain[] base = baseDomains.get(0);
        assertEquals("ProtectionDomain Count", 1, base.length);

        assertEquals("Our CodeSource", ourCodeSource, base[0].getCodeSource().getLocation());
    }

    @Test
    public void testGetPropertyPrivileged() {
        assertEquals("Retrieved property", VALUE,  WildFlySecurityManager.getPropertyPrivileged(KEY, null));

        List<ProtectionDomain[]> baseDomains = securityManager.reset();
        assertEquals("Expected checkPermission Calls", 1, baseDomains.size());

        /*
         * As this is a privileged call the call through the WildFlySecurityManager should be eliminated
         * from the ProtectionDomain stack.
         *
         * However internally ReadPropertyAction is used which is the same ProtectionDomain
         * as WildFlySecurityManager, also as with the testGetPropertyAction there are two reasons for
         * the test-classes ProtectionDomain to be within the list.  Duplicates in the list are
         * "optimised" out of the list leaving two protection domains.
         */

        ProtectionDomain[] base = baseDomains.get(0);
        assertEquals("ProtectionDomain Count", 2, base.length);
        assertEquals("Our CodeSource", ourCodeSource, base[0].getCodeSource().getLocation());
    }

    @Test
    public void testDoUnchecked() {
        /*
         * doUnchecked is the equivalent of a call to doPrivileged.
         */

        String value = AccessController.doPrivileged(new CustomAction());
        assertEquals("Retrieved property", VALUE,  value);

        List<ProtectionDomain[]> baseDomains = securityManager.reset();
        assertEquals("Expected checkPermission Calls", 1, baseDomains.size());

        value = WildFlySecurityManager.doUnchecked(new CustomAction());
        assertEquals("Retrieved property", VALUE,  value);

        List<ProtectionDomain[]> actualDomains = securityManager.reset();
        assertEquals("Expected checkPermission Calls", 1, actualDomains.size());

        ProtectionDomain[] base = addSecurityManagerProtectionDomain(baseDomains.get(0));
        ProtectionDomain[] actual = actualDomains.get(0);

        assertEquals("Matching ProtectionDomain[] size.", base.length, actual.length);
        for (int i = 0; i < base.length; i++) {
            assertEquals("Matching CodeSource Location", base[i].getCodeSource().getLocation(), actual[i].getCodeSource().getLocation());
        }
    }

    @Test
    public void testDoUnchecked_WithContext() {
        String value = AccessController.doPrivileged(new CustomAction(), context);
        assertEquals("Retrieved property", VALUE,  value);

        List<ProtectionDomain[]> baseDomains = securityManager.reset();
        assertEquals("Expected checkPermission Calls", 1, baseDomains.size());

        value = WildFlySecurityManager.doUnchecked(new CustomAction(), context);
        assertEquals("Retrieved property", VALUE,  value);

        List<ProtectionDomain[]> actualDomains = securityManager.reset();
        assertEquals("Expected checkPermission Calls", 1, actualDomains.size());

        ProtectionDomain[] base = addSecurityManagerProtectionDomain(baseDomains.get(0));
        ProtectionDomain[] actual = actualDomains.get(0);

        assertEquals("Matching ProtectionDomain[] size.", base.length, actual.length);
        for (int i = 0; i < base.length; i++) {
            assertEquals("Matching CodeSource Location", base[i].getCodeSource().getLocation(), actual[i].getCodeSource().getLocation());
        }

        value = WildFlySecurityManager.doUnchecked(KEY, new CustomAction(), context);
        assertEquals("Retrieved property", VALUE,  value);

        List<ProtectionDomain[]> parameterDomains = securityManager.reset();
        assertEquals("Expected checkPermission Calls", 1, parameterDomains.size());

        ProtectionDomain[] parameter = parameterDomains.get(0);
        assertEquals("Matching ProtectionDomain[] size.", base.length, parameter.length);
        for (int i = 0; i < base.length; i++) {
            assertEquals("Matching CodeSource Location", base[i].getCodeSource().getLocation(), parameter[i].getCodeSource().getLocation());
        }
    }

    @Test
    public void testDoChecked() {
        String value = WildFlySecurityManager.doChecked(new CustomAction());
        assertEquals("Retrieved property", VALUE,  value);

        List<ProtectionDomain[]> baseDomains = securityManager.reset();
        assertEquals("Expected checkPermission Calls", 1, baseDomains.size());

        value = WildFlySecurityManager.doChecked(KEY, new CustomAction());
        assertEquals("Retrieved property", VALUE,  value);

        List<ProtectionDomain[]> actualDomains = securityManager.reset();
        assertEquals("Expected checkPermission Calls", 1, actualDomains.size());

        ProtectionDomain[] base = baseDomains.get(0);
        ProtectionDomain[] actual = actualDomains.get(0);

        assertEquals("Matching ProtectionDomain[] size.", base.length, actual.length);
        for (int i = 0; i < base.length; i++) {
            assertEquals("Matching CodeSource Location", base[i].getCodeSource().getLocation(), actual[i].getCodeSource().getLocation());
        }
    }

    @Test
    public void testDoChecked_WithContext() {
        String value = WildFlySecurityManager.doChecked(new CustomAction(), context);
        assertEquals("Retrieved property", VALUE,  value);

        List<ProtectionDomain[]> baseDomains = securityManager.reset();
        assertEquals("Expected checkPermission Calls", 1, baseDomains.size());

        value = WildFlySecurityManager.doChecked(KEY, new CustomAction(), context);
        assertEquals("Retrieved property", VALUE,  value);

        List<ProtectionDomain[]> actualDomains = securityManager.reset();
        assertEquals("Expected checkPermission Calls", 1, actualDomains.size());

        ProtectionDomain[] base = baseDomains.get(0);
        ProtectionDomain[] actual = actualDomains.get(0);

        assertEquals("Matching ProtectionDomain[] size.", base.length, actual.length);
        for (int i = 0; i < base.length; i++) {
            assertEquals("Matching CodeSource Location", base[i].getCodeSource().getLocation(), actual[i].getCodeSource().getLocation());
        }
    }

    @Test
    public void testDoPrivilegedWithParameter() {
        String value = AccessController.doPrivileged(new CustomAction());
        assertEquals("Retrieved property", VALUE,  value);

        List<ProtectionDomain[]> baseDomains = securityManager.reset();
        assertEquals("Expected checkPermission Calls", 1, baseDomains.size());

        value = WildFlySecurityManager.doPrivilegedWithParameter(KEY, new CustomAction());
        assertEquals("Retrieved property", VALUE,  value);

        List<ProtectionDomain[]> actualDomains = securityManager.reset();
        assertEquals("Expected checkPermission Calls", 1, actualDomains.size());

        ProtectionDomain[] base = addSecurityManagerProtectionDomain(baseDomains.get(0));
        ProtectionDomain[] actual = actualDomains.get(0);

        assertEquals("Matching ProtectionDomain[] size.", base.length, actual.length);
        for (int i = 0; i < base.length; i++) {
            assertEquals("Matching CodeSource Location", base[i].getCodeSource().getLocation(), actual[i].getCodeSource().getLocation());
        }
    }

    @Test
    public void testDoPrivilegedWithParameter_WithContext() {
        String value = AccessController.doPrivileged(new CustomAction(), context);
        assertEquals("Retrieved property", VALUE,  value);

        List<ProtectionDomain[]> baseDomains = securityManager.reset();
        assertEquals("Expected checkPermission Calls", 1, baseDomains.size());

        value = WildFlySecurityManager.doPrivilegedWithParameter(KEY, new CustomAction(), context);
        assertEquals("Retrieved property", VALUE,  value);

        List<ProtectionDomain[]> actualDomains = securityManager.reset();
        assertEquals("Expected checkPermission Calls", 1, actualDomains.size());

        ProtectionDomain[] base = addSecurityManagerProtectionDomain(baseDomains.get(0));
        ProtectionDomain[] actual = actualDomains.get(0);

        assertEquals("Matching ProtectionDomain[] size.", base.length, actual.length);
        for (int i = 0; i < base.length; i++) {
            assertEquals("Matching CodeSource Location", base[i].getCodeSource().getLocation(), actual[i].getCodeSource().getLocation());
        }
    }

    private static ProtectionDomain[] getProtectionDomainStack(final AccessControlContext context) {
        ProtectionDomain[] domains = (ProtectionDomain[]) unsafe.getObject(context, pdStackOffset);
        /*
         * The call to doPrivileged adds an empty ProtectionDomain so filter it from the list.
         */
        ArrayList<ProtectionDomain> filteredDomains = new ArrayList<>();
        for (ProtectionDomain current : domains) {
            if (current.getClassLoader() != null || current.getCodeSource() != null || current.getPermissions() != null
                    || (current.getPrincipals() != null && current.getPrincipals().length > 0)) {
                filteredDomains.add(current);
            }
        }

        return filteredDomains.toArray(new ProtectionDomain[filteredDomains.size()]);
    }

    private static ProtectionDomain[] addSecurityManagerProtectionDomain(ProtectionDomain[] original) {
        ProtectionDomain managerDomain = WildFlySecurityManager.class.getProtectionDomain();
        for (ProtectionDomain current : original) {
            if (current.equals(managerDomain)) {
                return original;
            }
        }

        ProtectionDomain[] response = new ProtectionDomain[original.length + 1];
        System.arraycopy(original, 0, response, 0, original.length);
        response[response.length - 1] = managerDomain;

        return response;
    }

    static class CustomSecurityManager extends SecurityManager {

        private final Stack<ProtectionDomain[]> calls = new Stack<>();

        List<ProtectionDomain[]> reset() {
            List<ProtectionDomain[]> response = new ArrayList<>(calls);
            calls.clear();

            return response;
        }

        @Override
        public void checkPermission(Permission permission) {
            if (INTERESTING_PERMISSION.equals(permission)) {
                System.out.println("Permission Check " + permission.toString());
                calls.push(getProtectionDomainStack(((AccessControlContext)getSecurityContext())));
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
