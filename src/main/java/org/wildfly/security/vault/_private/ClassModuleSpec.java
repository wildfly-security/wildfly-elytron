/*
 * JBoss, Home of Professional Open Source
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
package org.wildfly.security.vault._private;

/**
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
public final class ClassModuleSpec {

    final String className;
    final String module;

    public ClassModuleSpec(String className, String module) {
        this.className = className;
        this.module = module;
    }

    public static ClassModuleSpec parse(final String classModuleSpec) {
        if (classModuleSpec == null) {
            throw new IllegalArgumentException("classModuleSpec==null");
        }
        int at = classModuleSpec.indexOf('@');
        return new ClassModuleSpec(at != -1 ? classModuleSpec.substring(0, at) : classModuleSpec,
            at != -1 ? classModuleSpec.substring(at + 1) : null);
    }

    public static String specString(final String className, final String module) {
        if (module == null) {
            return className;
        } else {
            return new StringBuilder(className).append('@').append(module).toString();
        }
    }

    public String specString() {
        return specString(className, module);
    }

    public String getClassName() {
        return className;
    }

    public String getModule() {
        return module;
    }
}
