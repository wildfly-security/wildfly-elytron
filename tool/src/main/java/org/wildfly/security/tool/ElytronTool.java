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

import org.apache.commons.cli.AlreadySelectedException;
import org.apache.commons.cli.Option;
import org.wildfly.security.WildFlyElytronProvider;

import java.security.Security;
import java.util.HashMap;
import java.util.Map;

/**
 * Elytron Tool main class which drives all registered commands.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
public class ElytronTool {

    public static final String LOG_MANAGER_PROPERTY = "java.util.logging.manager";
    /**
     * status code for unrecognized command
     */
    public static int ElytronToolExitStatus_unrecognizedCommand = 1;
    /**
     * status code for no problems
     */
    public static int ElytronToolExitStatus_OK = 0;

    private Map<String, Command> commandRegistry = new HashMap<>();
    /**
     * Name of the script used to execute the tool.
     */
    private String scriptName = null;


    /**
     * Construct ElytronTool with registration of all supported commands.
     */
    public ElytronTool() {
        commandRegistry.put(CredentialStoreCommand.CREDENTIAL_STORE_COMMAND, new CredentialStoreCommand()); // assigned exit codes 5 - 10
        commandRegistry.put(MaskCommand.MASK_COMMAND, new MaskCommand()); // uses exit code 7
        commandRegistry.put(VaultCommand.VAULT_COMMAND, new VaultCommand()); // uses exit code 7
        commandRegistry.put(FileSystemRealmCommand.FILE_SYSTEM_REALM_COMMAND, new FileSystemRealmCommand()); // uses exit code 7
        commandRegistry.put(FileSystemEncryptRealmCommand.FILE_SYSTEM_ENCRYPT_COMMAND, new FileSystemEncryptRealmCommand()); // uses exit code 7
        commandRegistry.put(FileSystemRealmIntegrityCommand.FILE_SYSTEM_REALM_INTEGRITY_COMMAND, new FileSystemRealmIntegrityCommand()); // uses exit code 7
    }

    /**
     * Main method to call from scripts.
     *
     * @param args parameters to pass farther. The first parameter is name or alias of the command.
     */
    public static void main(String[] args) {
        configureLogManager();

        Security.addProvider(new WildFlyElytronProvider());

        ElytronTool tool = new ElytronTool();
        if (args != null && args.length > 0) {
            if (args[0].startsWith("{")) {
                tool.scriptName = args[0].substring(1, args[0].indexOf('}'));
                args[0] = args[0].substring(args[0].indexOf('}') + 1);
            }
            Command command = tool.findCommand(args[0]);
            if (command != null && tool.scriptName != null) {
                command.setToolCommand(tool.scriptName);
            }
            String[] newArgs = new String[args.length -1];
            System.arraycopy(args, 1, newArgs, 0, args.length -1);
            if (command != null && newArgs.length > 0) {
                try {
                    command.execute(newArgs);
                    System.exit(command.getStatus());
                } catch (Exception e) {
                    if (e instanceof AlreadySelectedException) {
                        Option option = ((AlreadySelectedException) e).getOption();
                        System.err.println(ElytronToolMessages.msg.longOptionDescription(option.getOpt(), option.getLongOpt()));
                    }
                    if (command.isEnableDebug()) {
                        System.err.println(ElytronToolMessages.msg.commandExecuteException());
                        e.printStackTrace(System.err);
                    } else {
                        if (e.getLocalizedMessage() != null && (e.getLocalizedMessage().startsWith("ELY")
                                || e instanceof org.apache.commons.cli.ParseException)) {
                            System.err.println(ElytronToolMessages.msg.commandExecuteException());
                            System.err.println(e.getLocalizedMessage());
                        } else {
                            System.err.println(ElytronToolMessages.msg.commandExecuteExceptionNoDebug());
                        }
                    }
                    System.exit(command.getStatus());
                }
            } else if ("--help".equals(args[0]) || "-h".equals(args[0])) {
                tool.generalHelp();
            } else if (command != null) {
                command.help();
            } else {
                if (args[0].trim().isEmpty() && newArgs.length == 0) {
                    tool.generalHelp();
                } else {
                    System.err.println(ElytronToolMessages.msg.commandOrAliasNotFound(args[0]));
                    System.exit(ElytronToolExitStatus_unrecognizedCommand);
                }
            }
        } else {
            // no arguments supplied, print general help message and exist.
            tool.generalHelp();
        }
    }

    private static void configureLogManager() {
        if (System.getProperty(LOG_MANAGER_PROPERTY) == null) {
            System.setProperty(LOG_MANAGER_PROPERTY, "org.jboss.logmanager.LogManager");
        }
    }

    private void generalHelp() {
        System.out.print(ElytronToolMessages.msg.generalHelpTitle());
        System.out.println();
        for (Command c: commandRegistry.values()) {
            if (scriptName != null) {
                c.setToolCommand(scriptName);
            }
            c.help();
            System.out.println();
        }
    }

    Command findCommand(String commandName) {
        Command command = commandRegistry.get(commandName);
        if (command != null) {
            return command;
        } else {
            // check alias
            for (Command c: commandRegistry.values()) {
                if (c.isAlias(commandName)) {
                    return c;
                }
            }
        }
        return null;
    }

}