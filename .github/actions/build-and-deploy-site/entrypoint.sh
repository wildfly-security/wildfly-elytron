#!/bin/bash
# Exit immediately if a pipeline returns a non-zero status.
set -e

echo "Starting build and deployment action"

REMOTE_REPO="https://${GITHUB_ACTOR}:${GITHUB_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"

echo "Installing project dependencies..."
bundle install

# Build the website using Jekyll
echo "Building website..."
bundle exec jekyll build
echo "Jekyll build finished successfully"

# _site contains the generated website, copy contents to gh-pages branch
echo "Preparing commit that copies the built site to the gh-pages branch"
git clone --quiet --branch=gh-pages --depth=1 $REMOTE_REPO gh-pages > /dev/null 2>&1
rsync -rl --exclude .git --exclude .gitignore --delete _site/ gh-pages/
cd gh-pages
git config user.name "${GITHUB_ACTOR}"
git config user.email "${GITHUB_ACTOR}@users.noreply.github.com"
git add -A .
git commit -m "Deploy to ${GITHUB_REPOSITORY} gh-pages branch - $(date)"

echo "Pushing to the ${GITHUB_REPOSITORY} gh-pages branch..."
git push $REMOTE_REPO gh-pages:gh-pages > /dev/null 2>&1

echo "New version of the website has been deployed"
