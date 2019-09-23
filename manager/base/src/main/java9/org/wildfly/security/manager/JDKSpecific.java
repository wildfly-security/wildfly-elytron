/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2018 Red Hat, Inc. and/or its affiliates.
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

import static java.security.AccessController.doPrivileged;

import java.lang.StackWalker.Option;
import java.security.PrivilegedAction;
import java.util.List;
import java.util.stream.Collectors;

/**
 * JDK-specific classes which are replaced for different JDK major versions. This class is for JDK 9.
 * @author <a href="mailto:jucook@redhat.com">Justin Cook</a>
 */
final class JDKSpecific {

    /*
     * Using StackWalker the OFFSET is the minimum number of StackFrames, the first will always be
     * JDKSpecific,getCallerClass(int), the second will always be the caller of this class.
     */
    private static final int OFFSET = 2;

    public static Class<?> getCallerClass(int n){
        // Although we know WildFlySecurityManager is making the call it may not be the actual SecurityManager
        // so we need to use doPrivileged instead of a doUnchecked unless we can be sure checking has been switched off.
        final StackWalker stackWalker = WildFlySecurityManager.isChecking() ?
                doPrivileged((PrivilegedAction<StackWalker>)JDKSpecific::getStackWalker) : getStackWalker();

        List<StackWalker.StackFrame> frames = stackWalker.walk(s ->
                s.limit(n + OFFSET).collect(Collectors.toList())
        );
        return frames.get(frames.size() - 1).getDeclaringClass();
    }

    private static StackWalker getStackWalker() {
        return StackWalker.getInstance(Option.RETAIN_CLASS_REFERENCE);
    }

}
