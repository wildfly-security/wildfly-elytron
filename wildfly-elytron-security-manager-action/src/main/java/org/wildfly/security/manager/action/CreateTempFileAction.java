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

import java.io.File;
import java.io.IOException;
import java.security.PrivilegedExceptionAction;

/**
 * A security action to create a temporary file.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class CreateTempFileAction implements PrivilegedExceptionAction<File> {

    private final String prefix;
    private final String suffix;
    private final File directory;

    /**
     * Construct a new instance.
     *
     * @param prefix the prefix to set
     * @param suffix the suffix to set
     * @param directory the directory
     */
    public CreateTempFileAction(final String prefix, final String suffix, final File directory) {
        this.prefix = prefix;
        this.suffix = suffix;
        this.directory = directory;
    }

    /**
     * Construct a new instance.
     *
     * @param prefix the prefix to set
     * @param suffix the suffix to set
     */
    public CreateTempFileAction(final String suffix, final String prefix) {
        this(prefix, suffix, null);
    }

    public File run() throws IOException {
        return File.createTempFile(prefix, suffix, directory);
    }
}
