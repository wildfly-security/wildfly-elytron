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

import java.util.ArrayList;
import java.util.List;

/**
 * Provides help for the Elytron Tool command
 *
 * @author <a href="mailto:pberan@redhat.com">Petr Beran</a>
 */
public class HelpCommand {

    private final List<HelpSection> helpSections;

    private HelpCommand(HelpCommandBuilder helpCommandBuilder) {
        this.helpSections = helpCommandBuilder.helpSections;
    }

    /**
     * Displays all sections for the help command
     */
    public void printHelp() {
        System.out.print(System.lineSeparator());
        for (HelpSection helpSection : helpSections){
            helpSection.printHelp();
        }
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

            HelpCommand helpCommand = new HelpCommand(this);
            return helpCommand;
        }
    }
}
