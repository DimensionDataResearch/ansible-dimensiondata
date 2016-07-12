
## README

This directory contains:
* info on what is required to support the README generation
* info on how to regenerate the **README_DD_api.md** file
* info on documentation issues regarding the README generation


### How to Support README Generation

Support code must be installed before you can regenerate the README file.  This support code is located in a github repo.  To install this repo, enter:
```
ansible-playbook ansible_installation.yml
```

This will create a directory called `ansible-webdocs`.  This directory contains code that is required by the next step.  Note: this code installation only needs to be done once per system.


### How to Regenerate the README file

The readme file is called *README_DD_api.md*.

**After** you have completed the steps in the previous section, your system should be ready to generate the README file.  To do this,:
```
  make_docs.sh
```
Running this code will invoke `ansible-playbook` on the *make_ansible_docs_playbook.yml* file.  This will end up:

* deleting the existing *README_DD_api.md* file
* generating a new *README_DD_api.md* file


Whenever you make changes to the `dimensiondata_*.py` code, you should regenerate the README file to ensure that any changes you had made were properly interpreted.


### Documentation Issues in the Python Code

The Dimension Data python code contains specially-formatted text which is used to generate the *README_DD_api.md* file.  There are some issues with how to document your code that affect the generation of the README file.  These are addressed in the file *Ansible_Webdocs_Notes.txt*.



