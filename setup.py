#!/usr/bin/python
# Copyright 2012 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from setuptools import setup

import swifts3


setup(name='swifts3',
    version=swifts3.version,
    description='The swifts3 middleware will emulate the S3 REST api on top '
                'of swift.',
    author='OpenStack, LLC.',
    author_email='ikharin@mirantis.com',
    packages=['swifts3'],
    requires=['swift(>=1.4)'],
    entry_points={'paste.filter_factory':
        ['swifts3=swifts3.middleware:filter_factory']})
