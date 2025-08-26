Contributing to WildFly Elytron
==================================

Welcome to the WildFly Elytron project! We welcome contributions from the community. This guide will walk you through the steps for getting started on our project.

- [Forking the Project](#forking-the-project)
- [Issues](#issues)
  - [Good First Issues](#good-first-issues)
- [Setting up your Developer Environment](#setting-up-your-developer-environment)
- [Contributing Guidelines](#contributing-guidelines)
  - [Testing](#testing)
  - [Pull Request Process](#pull-request-process)
  - [Documentation](#documentation)
- [FAQ for New Contributors](#faq-for-new-contributors)
- [Community](#community)


## Forking the Project 
To contribute, you will first need to fork the [wildfly-elytron](https://github.com/wildfly-security/wildfly-elytron) repository. 

This can be done by looking in the top-right corner of the repository page and clicking "Fork".
![fork](assets/images/fork.jpg)

The next step is to clone your newly forked repository onto your local workspace. This can be done by going to your newly forked repository, which should be at `https://github.com/USERNAME/wildfly-elytron`. 

Then, there will be a green button that says "Code". Click on that and copy the URL.

![clone](assets/images/clone.png)

Then, in your terminal, paste the following command:
```bash
git clone [URL]
```
Be sure to replace [URL] with the URL that you copied.

Now you have the repository on your computer!

## Issues
The WildFly Elytron project uses JIRA to manage issues. All issues can be found [here](https://issues.redhat.com/projects/ELY/issues). 

To create a new issue, comment on an existing issue, or assign an issue to yourself, you'll need to first [create a JIRA account](https://issues.redhat.com/).


### Good First Issues
Want to contribute to the WildFly Elytron project but aren't quite sure where to start? Check out our issues with the `good-first-issue` label. These are a triaged set of issues that are great for getting started on our project. These can be found [here](https://issues.redhat.com/issues/?filter=12383825). 

Once you have selected an issue you'd like to work on, make sure it's not already assigned to someone else. To assign an issue to yourself, simply click on "Start Progress". This will automatically assign the issue to you.

![jira](assets/images/jira_start_progress.png)

It is recommended that you use a separate branch for every issue you work on. To keep things straightforward and memorable, you can name each branch using the JIRA issue number. This way, you can have multiple PRs open for different issues. For example, if you were working on [ELY-2127](https://issues.redhat.com/browse/ELY-2127), you could use ELY-2127 as your branch name.

## Setting up your Developer Environment
You will need:

* JDK 11
* Git
* Maven 3.3.9 or later
* An [IDE](https://en.wikipedia.org/wiki/Comparison_of_integrated_development_environments#Java)
(e.g., [IntelliJ IDEA](https://www.jetbrains.com/idea/download/), [Eclipse](https://www.eclipse.org/downloads/), etc.)

For instructions that will walk you through how to install Git, Java, and Maven for your operating system, and show you how to fork and clone the WildFly Elytron project, take a look at our [setup guides](https://wildfly-security.github.io/wildfly-elytron/guides/).

First `cd` to the directory where you cloned the project (eg: `cd wildfly-elytron`)

Add a remote ref to upstream, for pulling future updates.
For example:

```
git remote add upstream https://github.com/wildfly-security/wildfly-elytron
```
To build `wildfly-elytron` run:
```bash
mvn clean install
```

To skip the tests, use:

```bash
mvn clean install -DskipTests=true
```

To run only a specific test, use:

```bash
mvn clean install -Dtest=TestClassName
```
Note: Some tests will fail if `localhost` is not listed first in `/etc/hosts` file for the loopback addresses (IPv4 and IPv6).

For more information, including details on how WildFly Elytron is integrated in WildFly Core and WildFly, check out our [developer guide](https://wildfly-security.github.io/wildfly-elytron/getting-started-for-developers/).


## Contributing Guidelines

### Testing
Ensure that your changes are thoroughly tested before submitting a pull request. Follow these testing guidelines:

- Run the existing unit tests using Maven: `mvn clean test`
- Include new unit tests for your code changes.

If applicable, provide instructions on how to run integration tests or any additional testing procedures.

### Pull Request Process
When submitting a PR, please keep the following guidelines in mind:

1. In general, it's good practice to squash all of your commits into a single commit. For larger changes, it's ok to have multiple meaningful commits. If you need help with squashing your commits, feel free to ask us how to do this on your pull request. We're more than happy to help!

2. Please include the JIRA issue you worked on in the title of your pull request and in your commit message. For example, for [ELY-2127](https://issues.redhat.com/browse/ELY-2127), the PR title and commit message should be `[ELY-2127] Add client side TRACE logging after successful authentication`.

3. Please include the link to the JIRA issue you worked on in the description of the pull request. For example, if your PR adds a fix for [ELY-2127](https://issues.redhat.com/browse/ELY-2127), the PR description should contain a link to https://issues.redhat.com/browse/ELY-2127.

For an example of a properly formatted PR, take a look at https://github.com/wildfly-security/wildfly-elytron/pull/1532

### Documentation
Contributors are encouraged to keep documentation up-to-date along with code changes. If your changes impact user-facing features, update the relevant documentation files in directory.
Community documentation can be found in the [wildfly repository](https://github.com/wildfly/wildfly/tree/main/docs)

## FAQ for New Contributors
Check out our [Frequently Asked Questions](https://wildfly-security.github.io/wildfly-elytron/blog/frequently-asked-questions-new-contributors/) for New Contributors.

## Code Reviews

All submissions, including submissions by project members, need to be reviewed by at least two WildFly Elytron committers before being merged.

The [GitHub Pull Request Review Process](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/reviewing-changes-in-pull-requests/about-pull-request-reviews) is followed for every pull request.

## Maintenance Branches

If you are working on a fix that's required for a maintenance branch (e.g., a fix for the 1.15.x or 2.2.x branches), please submit
your PR directly against the relevant maintenance branch. Once a fix for a maintenance branch is approved and merged, we then
merge the maintenance branch to the upstream branch to ensure changes are kept in sync.

## Community
For more information on how to get involved with WildFly Elytron, check out our [community](https://wildfly-security.github.io/wildfly-elytron/community/) page.