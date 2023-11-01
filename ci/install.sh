#!/bin/bash

if [ "$RUN_TYPE" = "coverage" ]; then
   sudo gem install coveralls-lcov
fi

pip3 install --user dataclasses-json Jinja2 importlib_resources pluginbase gitpython
