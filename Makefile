# Copyright 2015-2018 Lionheart Software LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Usage: make VERSION=0.1.2

PODFILE := $(shell find . -name "*.podspec" -depth 1)

all: publish

version_provided:
	test -n "$(VERSION)"

podspec_found:
	test -n "$(PODFILE)"

quicklint:
	bundle exec pod spec lint --quick

tag: podspec_found version_provided quicklint
	sed -i "" "s/\(s.version[ ]*=[ ]\).*/\1 \"$(VERSION)\"/g" $(PODFILE)
	git add .
	# - ignores errors in this command
	-git commit -m "bump version to $(VERSION)"
	# Delete tag if already exists
	-git tag -d $(VERSION)
	-git push origin master :$(VERSION)
	git tag $(VERSION)
	git push origin master
	git push --tags

publish: tag
	bundle exec pod trunk push
