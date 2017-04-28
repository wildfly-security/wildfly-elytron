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

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
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
     * @throws Exception
     */
    protected String prompt(boolean echo, String prompt, boolean confirm, String confirmPrompt) throws Exception {
        Console console = System.console();
        if (echo || console == null) {
            try (BufferedReader in = new BufferedReader(new InputStreamReader(System.in))) {
                String first = console != null ? console.readLine(prompt) : in.readLine();
                if (first != null && confirm) {
                    String second = console != null ? console.readLine(confirmPrompt) : in.readLine();
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
            } catch (IOException e) {
                setStatus(GENERAL_CONFIGURATION_ERROR);
                throw new Exception(e);
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

    /**
     * Alerts if any of the command line options used are duplicated
     * @param cmdLine the command line options used when invoking the command, after parsing
     */
    public void printDuplicatesWarning(CommandLine cmdLine) {
        List<Option> optionsList = new ArrayList<>(Arrays.asList(cmdLine.getOptions()));
        Set<Option> duplicatesSet = new HashSet<>();
        for (Option option : cmdLine.getOptions()) {
            if (Collections.frequency(optionsList, option) > 1) {
                duplicatesSet.add(option);
            }
        }

        for (Option option : duplicatesSet) {
            System.out.println(ElytronToolMessages.msg.duplicateOptionSpecified(option.getLongOpt()));
        }
    }

    /**
     * Alerts if any of the command line options used are duplicated, excluding commands
     * that are allowed to have duplicates
     * @param cmdLine the command line options used when invoking the command, after parsing
     * @param duplicatesAllowed list of the commands line options that can be duplicated. For example:
     *                          <code>
     *                              List<String> allowedDuplicates = new ArrayList<String>()
     *                                  {{ add(PASSWORD_CREDENTIAL_VALUE_PARAM);
 *                                  }};
     *                          </code>
     */
    public void printDuplicatesWarning(CommandLine cmdLine, List<String> duplicatesAllowed) {
        if (duplicatesAllowed == null) {
            return;
        }

        List<Option> optionsList = new ArrayList<>(Arrays.asList(cmdLine.getOptions()));
        Set<Option> duplicatesSet = new HashSet<>();
        for (Option option : cmdLine.getOptions()) {
            if (Collections.frequency(optionsList, option) > 1 && !duplicatesAllowed.contains(option.getLongOpt())) {
                duplicatesSet.add(option);
            }
        }

        for (Option option : duplicatesSet) {
            System.out.println(ElytronToolMessages.msg.duplicateOptionSpecified(option.getLongOpt()));
        }
    }
}
