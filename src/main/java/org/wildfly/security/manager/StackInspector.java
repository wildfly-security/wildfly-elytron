/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2013 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.manager;

import static java.lang.Math.max;
import static java.lang.Math.min;
import static java.lang.System.getSecurityManager;
import static java.util.Arrays.copyOfRange;

import java.security.Permission;

/**
 * A utility class which is useful for inspecting the call stack.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class StackInspector {

    private static final Permission GET_STACK_INSPECTOR_PERMMISSION = new RuntimePermission("getStackInspector");
    private static final StackInspector INSTANCE = new StackInspector();

    private StackInspector() {
    }

    /**
     * Get the singleton {@code StackInspector} instance.  The caller must have the {@code getStackInspector}
     * {@link RuntimePermission}.
     *
     * @return the singleton {@code StackInspector} instance
     */
    public static StackInspector getInstance() {
        if (WildFlySecurityManager.isChecking()) {
            getSecurityManager().checkPermission(GET_STACK_INSPECTOR_PERMMISSION);
        }
        return INSTANCE;
    }

    /**
     * Get the caller class.  The {@code skipFrames} argument specifies how many spots to go back
     * on the call stack; 0 indicates the immediate caller.
     *
     * @param skipFrames the number of frames to skip over before the immediate caller
     * @return the caller class
     */
    public Class<?> getCallerClass(int skipFrames) {
        return WildFlySecurityManager.getCallerClass(max(0, skipFrames) + 2);
    }

    /**
     * Get all or a portion of the call stack.  The {@code numFrames} arguement specifies how many frames should be
     * returned.
     *
     * @param skipFrames the number of frames to skip; 0 will include the immediate caller at index 0
     * @param numFrames the maximum number of frames to return
     * @return the partial call stack
     */
    public Class<?>[] getCallStack(int skipFrames, int numFrames) {
        final Class<?>[] stack = WildFlySecurityManager.getCallStack();
        final int from = max(0, skipFrames) + 2;
        return copyOfRange(stack, from, min(from + numFrames, stack.length));
    }

    /**
     * Get all or a portion of the call stack.  The {@code numFrames} arguement specifies how many frames should be
     * returned.
     *
     * @param skipFrames the number of frames to skip; 0 will include the immediate caller at index 0
     * @return the partial call stack
     */
    public Class<?>[] getCallStack(int skipFrames) {
        final Class<?>[] stack = WildFlySecurityManager.getCallStack();
        final int from = max(0, skipFrames) + 2;
        return copyOfRange(stack, from, stack.length);
    }

    /**
     * Get the call stack.
     *
     * @return the call stack
     */
    public Class<?>[] getCallStack() {
        final Class<?>[] stack = WildFlySecurityManager.getCallStack();
        return copyOfRange(stack, 2, stack.length);
    }

    /**
     * Determine whether the call stack contains a given class.  Useful for assertions.
     *
     * @param clazz the class to test
     * @return {@code true} if the call stack contains the class
     */
    public boolean callStackContains(Class<?> clazz) {
        final Class<?>[] stack = WildFlySecurityManager.getCallStack();
        for (int i = 2; i < stack.length; i ++) {
            if (stack[i] == clazz) return true;
        }
        return false;
    }
}
