# Elytron Project Website Based on Jekyll

## Getting Started

These instructions will allow you to run the Elytron website locally for development and testing purposes.

### Installation
The following steps are based on the [Jekyll static site generator docs](https://jekyllrb.com/docs/).

1. Install a full [Ruby development environment](https://jekyllrb.com/docs/installation/)
2. Install jekyll and [bundler](https://jekyllrb.com/docs/ruby-101/#bundler)  [gems](https://jekyllrb.com/docs/ruby-101/#gems) 
  
        gem install jekyll bundler

3. Fork the [project repository](https://github.com/wildfly-security/wildfly-elytron), then clone your fork.
  
        git clone git@github.com:YOUR_USER_NAME/wildfly-elytron.git

4. Change into the project directory:
  
        cd wildfly-elytron

5. Checkout the [develop](https://github.com/wildfly-security/wildfly-elytron/tree/develop) branch:
  
        git checkout develop

6. Use bundler to fetch all required gems in their respective versions

        bundle install

7. Build the site and make it available on a local server
  
        bundle exec jekyll serve

   If you encounter the following message:

        FATAL: Listen error: unable to monitor directories for changes.  
        
   Please refer to these [instructions](https://github.com/guard/listen/wiki/Increasing-the-amount-of-inotify-watchers) to fix this.       
        
8. Now browse to http://localhost:4000/wildfly-elytron/

> If you encounter any unexpected errors during the above, please refer to the [troubleshooting](https://jekyllrb.com/docs/troubleshooting/#configuration-problems) page or the [requirements](https://jekyllrb.com/docs/installation/#requirements) page, as you might be missing development headers or other prerequisites.


**For more regarding the use of Jekyll, please refer to the [Jekyll Step by Step Tutorial](https://jekyllrb.com/docs/step-by-step/01-setup/).**

## Writing a blog post

To write a blog post:

- Add an author entry in [_data/authors.yaml](https://github.com/wildfly-security/wildfly-elytron/tree/develop/_data/authors.yaml)
    - `emailhash` is used to fetch your picture from the Gravatar service
- Create a blog post entry under [_posts](https://github.com/wildfly-security/wildfly-elytron/tree/develop/_posts)
    - The file name should be `yyyy-mm-dd-slug.adoc`
- Your blog post should be in asciidoc format (take a look at other blogs posts in the _posts directory to see examples)
    - To view your blog post without needing to build locally, the following steps can be used:
        - If you haven't done so already, generate a GitHub token following the instructions
          [here](https://help.github.com/en/github/authenticating-to-github/creating-a-personal-access-token-for-the-command-line#creating-a-token)
          (in step 7, you only need to select "public_repo"). Use this value to add a `PUSH_GITHUB_TOKEN` secret to your
          repository settings (i.e., https://github.com/<YOUR_GITHUB_USERNAME>/wildfly-elytron/settings).
        - Simply push your changes to the `develop` branch on your `wildfly-elytron` fork. This will trigger a website
          build that will get pushed to the `gh-pages` branch on your fork. Then browse to
          http://<YOUR_GITHUB_USERNAME>.github.io/wildfly-elytron/blog and click on your post.
    - To view your blog post locally, first follow the instructions [above](https://github.com/wildfly-security/wildfly-elytron/tree/develop#installation) to build the Elytron website
      locally. Then browse to http://localhost:4000/wildfly-elytron/blog and click on your post.
- Submit a pull request against the `wildfly-elytron` `develop` branch

