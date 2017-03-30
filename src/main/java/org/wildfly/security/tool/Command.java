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

import java.io.Console;
import java.util.Arrays;
import java.util.Collections;
import java.util.Set;

/**
 * Base command class
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
public abstract class Command {

    /**
     * General configuration error exit code.
     */
    public static int GENERAL_CONFIGURATION_ERROR = 7;

    public static int INPUT_DATA_NOT_CONFIRMED = 3;

    private int status = 255;

    public abstract void execute(String[] args) throws Exception;

    /**
     * Default help line width.
     */
    public static int WIDTH = 1024;

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

    /**
     * Prompt for interactive user input with possible confirmation of input data.
     * When data are not confirmed tool exits with {@link #INPUT_DATA_NOT_CONFIRMED} exit code
     *
     * @param echo echo the characters typed
     * @param prompt text to display before the input
     * @param confirm confirm data after the first input
     * @param confirmPrompt confirmation text
     * @return data as user inputs it
     */
    protected String prompt(boolean echo, String prompt, boolean confirm, String confirmPrompt) {
        Console console = System.console();
        if (console == null) {
            System.err.println(ElytronToolMessages.msg.cannotPromptConsoleMissing());
            System.exit(GENERAL_CONFIGURATION_ERROR);
        }
        if (echo) {
            String first = console.readLine(prompt);
            if (first != null && confirm) {
                String second = console.readLine(confirmPrompt);
                if (first.equals(second)) {
                    return first;
                } else {
                    System.err.println(ElytronToolMessages.msg.inputDataNotConfirmed());
                    System.exit(INPUT_DATA_NOT_CONFIRMED);
                    return null;
                }
            } else {
                return first;
            }
        } else {
            char[] inVisible = console.readPassword(prompt != null ? prompt : "Password:");
            if (inVisible != null && confirm) {
                char[] inVisible2 = console.readPassword(confirmPrompt != null ? confirmPrompt : "Confirm password:");
                if (Arrays.equals(inVisible, inVisible2)) {
                    return new String(inVisible);
                } else {
                    System.err.println(ElytronToolMessages.msg.inputDataNotConfirmed());
                    System.exit(INPUT_DATA_NOT_CONFIRMED);
                    return null;
                }
            }
            if (inVisible != null) {
                return new String(inVisible);
            }
            return null;
        }
    }

}
