/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.manager.action;

import java.security.PrivilegedAction;

/**
 * A security action to create a thread.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class CreateThreadAction implements PrivilegedAction<Thread> {

    private final ThreadGroup group;
    private final Runnable target;
    private final String name;
    private final long stackSize;

    /**
     * Construct a new instance.
     *
     * @param name the name of the thread (may not be {@code null})
     */
    public CreateThreadAction(final String name) {
        this(null, null, name, 0L);
    }

    /**
     * Construct a new instance.
     *
     * @param group the thread group to use
     * @param name the name of the thread (may not be {@code null})
     */
    public CreateThreadAction(final ThreadGroup group, final String name) {
        this(group, null, name, 0L);
    }

    /**
     * Construct a new instance.
     *
     * @param target the runnable target
     * @param name the name of the thread (may not be {@code null})
     */
    public CreateThreadAction(final Runnable target, final String name) {
        this(null, target, name, 0L);
    }

    /**
     * Construct a new instance.
     *
     * @param group the thread group to use
     * @param target the runnable target
     * @param name the name of the thread (may not be {@code null})
     */
    public CreateThreadAction(final ThreadGroup group, final Runnable target, final String name) {
        this(group, target, name, 0L);
    }

    /**
     * Construct a new instance.
     *
     * @param group the thread group to use
     * @param target the runnable target
     * @param name the name of the thread (may not be {@code null})
     * @param stackSize the stack size to use
     */
    public CreateThreadAction(final ThreadGroup group, final Runnable target, final String name, final long stackSize) {
        this.group = group;
        this.target = target;
        this.name = name;
        this.stackSize = stackSize;
    }

    public Thread run() {
        return new Thread(group, target, name, stackSize);
    }
}
