#!/bin/bash
#
#  Build documentation using jazzy:
#    [sudo] bundle install

bundle exec jazzy \
	-o "docs" \
	--min-acl "internal" \
	--module-version "$(git describe --tags --always)"
