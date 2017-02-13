/*
 * JBoss, Home of Professional Open Source
 * Copyright 2017 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.tool;

import java.util.Collections;
import java.util.Set;

/**
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
public abstract class Command {

    private int status = 255;

    public abstract void execute(String[] args) throws Exception;


    /**
     * Display help to the command.
     *
     */
    public void help() {

    }

    public boolean isAlias(String alias) {
        return aliases().contains(alias);
    }

    protected Set<String> aliases() {
        return Collections.emptySet();
    }

    public int getStatus() {
        return status;
    }

    protected void setStatus(int status) {
        this.status = status;
    }

    public static boolean isWindows() {
        String opsys = System.getProperty("os.name").toLowerCase();
        return (opsys.indexOf("win") >= 0);
    }

}
