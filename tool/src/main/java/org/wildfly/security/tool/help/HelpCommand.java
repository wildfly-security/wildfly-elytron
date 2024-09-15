/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2024 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.wildfly.security.tool.help;

import org.aesh.readline.tty.terminal.TerminalConnection;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;

/**
 * Provides help for the Elytron Tool command
 *
 * @author <a href="mailto:pberan@redhat.com">Petr Beran</a>
 */
public class HelpCommand {

    private final List<HelpSection> helpSections;
    private static TerminalConnection terminalConnection;

    private HelpCommand(HelpCommandBuilder helpCommandBuilder) {
        this.helpSections = helpCommandBuilder.helpSections;
    }

    /**
     * Displays all sections for the help command
     */
    public void printHelp() {
        if (terminalConnection == null) {
            try {
                terminalConnection = new TerminalConnection(Charset.defaultCharset(), System.in, System.out);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        terminalConnection.write(System.lineSeparator());
        for (HelpSection helpSection : helpSections){
            helpSection.printHelp();
        }
        terminalConnection.close();
    }

    public static TerminalConnection getTerminal() {
        return terminalConnection;
    }

    public static class HelpCommandBuilder {

        private UsageSection usageSection;
        private DescriptionSection descriptionSection;
        private CommandsSection commandsSection;
        private OptionsSection optionsSection;

        private final List<HelpSection> helpSections = new ArrayList<>();

        private HelpCommandBuilder() {}

        public static HelpCommandBuilder builder() {
            return new HelpCommandBuilder();
        }

        public HelpCommandBuilder usage(UsageSection usageSection) {
            this.usageSection = usageSection;
            return this;
        }

        public HelpCommandBuilder description(DescriptionSection descriptionSection) {
            this.descriptionSection = descriptionSection;
            return this;
        }

        public HelpCommandBuilder commands(CommandsSection commandsSection) {
            this.commandsSection = commandsSection;
            return this;
        }

        public HelpCommandBuilder options(OptionsSection optionsSection) {
            this.optionsSection = optionsSection;
            return this;
        }

        public HelpCommand build() {
            // Ensures that all sections are in specific order and the order cannot be tampered with
            if (descriptionSection != null) {
                helpSections.add(descriptionSection);
            }
            if (usageSection != null) {
                helpSections.add(usageSection);
            }
            if (commandsSection != null) {
                helpSections.add(commandsSection);
            }
            if (optionsSection != null) {
                helpSections.add(optionsSection);
            }
            return new HelpCommand(this);
        }
    }
}
