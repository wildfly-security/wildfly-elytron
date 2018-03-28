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
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.function.Supplier;

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

    private List<String> redirectionValues;

    private boolean enableDebug;

    /**
     * Command used to execute the tool.
     */
    private String toolCommand = "java -jar wildfly-elytron-tool.jar";

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
            if (console == null && redirectionValues == null) {
                try (BufferedReader in = new BufferedReader(new InputStreamReader(System.in))) {
                    redirectionValues = new ArrayList<>();
                    String value;
                    while ((value = in.readLine()) != null) {
                        redirectionValues.add(value);
                    }
                } catch (IOException e) {
                    setStatus(GENERAL_CONFIGURATION_ERROR);
                    throw new Exception(e);
                }
            }
            String first = console != null ? console.readLine(prompt)
                    : (redirectionValues.size() == 0 ? null : redirectionValues.remove(0));
            if (first != null && confirm) {
                String second = console != null ? console.readLine(confirmPrompt)
                        : (redirectionValues.size() == 0 ? null : redirectionValues.remove(0));
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

    /**
     * Get the command debug option
     */
    public boolean isEnableDebug() {
        return enableDebug;
    }

    /**
     * Set the command debug option
     */
    public void setEnableDebug(boolean enableDebug) {
        this.enableDebug = enableDebug;
    }

    /**
     * Get tool command
     */
    public String getToolCommand() {
        return toolCommand;
    }

    /**
     * Set tool command
     */
    public void setToolCommand(String toolCommand) {
        this.toolCommand = toolCommand;
    }

    protected Supplier<Provider[]> getProvidersSupplier(final String providersList) {
        return () -> {
            if (providersList != null && !providersList.isEmpty()) {
                final String[] providerNames = providersList.split(",");
                List<Provider> providers = new ArrayList<>(providerNames.length);
                for(String p: providerNames) {
                    Provider provider = Security.getProvider(p.trim());
                    if (provider != null) {
                        providers.add(provider);
                    }
                }
                ServiceLoader<Provider> providerLoader = ServiceLoader.load(Provider.class);
                for (Provider provider : providerLoader) {
                    for (String p : providerNames) {
                        if (provider.getName().equals(p)) {
                            providers.add(provider);
                            break;
                        }
                    }
                }
                if (providers.isEmpty()) {
                    throw ElytronToolMessages.msg.unknownProvider(providersList);
                }
                return providers.toArray(new Provider[providers.size()]);
            } else {
                // when no provider list is specified, load all Providers from service loader except WildFlyElytron Provider
                ServiceLoader<Provider> providerLoader = ServiceLoader.load(Provider.class);
                Iterator<Provider> providerIterator = providerLoader.iterator();
                List<Provider> providers = new ArrayList<>();
                while (providerIterator.hasNext()) {
                    Provider provider = providerIterator.next();
                    if (provider.getName().equals("WildFlyElytron")) continue;
                    providers.add(provider);
                }
                return providers.toArray(new Provider[providers.size()]);
            }
        };
    }
}
