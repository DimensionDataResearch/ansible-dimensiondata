Dimension Data Ansible Module
=============================

This repo "supports" both the DimensionDataResearch ansible-related repos.

Specifically,
  - core Ansible at ( https://github.com/DimensionDataResearch/ansible )
  - Ansible modules extras at ( https://github.com/DimensionDataResearch/ansible-modules-extras )

This repo provides Dimension-Data custom documentation as well as Ansible demo
code.


Git Submodules
==============

This repo contains git submodules for:
  - ansible
  - ansible-modules-extras

These submodules are references to other repos.  This allows us to "include" the other repos in our repo.
However, if you push out an update to one of those directories of this repo,
it will actually go to the other repos (not to this one).


Installation
============

Here are installation steps that have been validated on Ubuntu:

All steps below should be done by a non root user

- Make sure our repo indexes are up-to-date:
    # sudo apt-get -y update 
- Install build dependencies for Ansible and its dependencies:
    # sudo apt-get install build-essential libssl-dev libffi-dev python-dev 
- Install virtual env which allows us to run isolated python environments without affecting system wide settings/packages:
    # virtualenv -p /usr/bin/python2.7 ~/.dd-mcp 
- Source the virtual env environment script to set paths to our created python virtual environment:
    # source ~/.virtualenvs/dd-mcp/bin/activate 
- Install latest libcloud code which contains bugfixes and enhancements required by MCP Ansible code:
    # pip install -e 'git+https://github.com/apache/libcloud#egg=apache-libcloud'
- Install Ansible from the DimensionData fork. This will only be necessary for a short time while Ansible team reviews our pull request
    # pip install -e ‘git+https://github.com/DimensionDataResearch/ansible.git@devel#egg=ansible'
- Create MCP Cloud credentials file (can also use env vars instead) .. Please replace items in <> with actual user and pass:
    # echo -ne "[dimensiondatacloud]\nDIDATA_USER: <username>\nDIDATA_PASSWORD: <password>\n" > ~/.dimensiondata

To run a playbook:
ansible-playbook -vvvv <playbookname>.yaml 
Example playbooks for all functionality can be found here:  https://github.com/DimensionDataResearch/ansible-dimensiondata/tree/develop/demo


Contributing
============

1. Fork it ( https://github.com/DimensionDataDevOps/ansible-dimensiondata/fork  )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

License
=======

Dimension Data Ansible Module is licensed under the Apache 2.0 license. For more information, please see LICENSE_ file.

.. _LICENSE: https://github.com/DimensionDataDevOps/ansible-dimensiondata/blob/master/LICENSE
