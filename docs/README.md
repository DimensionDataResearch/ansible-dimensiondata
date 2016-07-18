
## README

This file contains:
* info on the Dimension Data API
* info on when to regenerate the HTML
* info on how to regenerate the HTML directory
* an example of a “Documentation Bug”
* info on documentation issues regarding the HTML generation

### Dimension Data API

Click [here](./html/index.html) to see details on the Dimension Data API.
The documentation lives (and is regenerated in) the html sub-directory.
The “file of interest” is at ./html/index.html .

### When to Regenerate the HTML

There is no need to update the HTML when we are just doing "low-level bug fixes" that don't affect the module level interfaces.
A build of rev X would still contain the documentation generated at rev X-1 (or X-2 or whatever).


Therefore, you only **need** to update (and submit) the HTML files when you have made a change to any of the "docstring" sections of the file.
You would only need to do this when:
* you are fixing a mistake/typo/clarification/etc.
* you made a change to the interface of one of the modules.
* you are making a new routine that needs to be documented


### How to Regenerate the README file

Assuming that your changes to the source code have been completed, do the following from a terminal window:

* cd into the docs subdirectory.
* ansible-playbook make_ansible_docs.yml

Running this script will:

* create an ansible_for_docs sub-directory.
* Run a script (which is part of the Ansible distribution) against the source code (creating RST files)
* Run Sphinx against the RST files (creating HTML files)

Note that the RST file generation is … “not very forgiving” in how it interprets the source code.

### Documentation Bug

Well, to be fair, these aren’t really documentation bugs; these are issues from the source code that aren’t handled well (or at all) by the documentation generation code.

Here’s an example of what I mean.
Go to ANY of the python source files, (say dimenstiondata_backup.py). Go to the DOCUMENTATION section.  Find the line (about 3 lines down) that starts with “description:”.  Note that the description is a list (i.e., the description is not on that line but on the next line and it is preceded by a a hyphen).  Note that the short_description field (the line above) is a string field (i.e., the short description itself follows the label short_description).

OK, so try editing the file so that description is a string value.  Do this by changing the description line from:

```
description:
  - blahs, blah, blah, whatever
```

to this:

```
description: blahs, blah, blah, whatever
```

OK, with that done, go regenerate the documentation.
What happens?

```
 ---------------------------
< TASK [make the rst files] >
 ---------------------------
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\

                ||----w |
                ||     ||

fatal: [localhost]: FAILED! => {"changed": true, "cmd": "make modules", "delta": "0:00:00.481187", "end": "2016-07-15 16:55:49.012006", "failed": true, "rc": 2, "start": "2016-07-15 16:55:48.530819", "stderr": " [ERROR]: unable to parse\n../lib/ansible/modules/extras/cloud/dimensiondata/dimensiondata_backup.py\n*** ERROR: MODULE MISSING DOCUMENTATION: ../lib/ansible/modules/extras/cloud/dimensiondata/dimensiondata_backup.py, dimensiondata_backup ***\nmake: *** [modules] Error 1", "stdout": "PYTHONPATH=../lib ../hacking/module_formatter.py -t rst --template-dir=../hacking/templates --module-dir=../lib/ansible/modules -o rst/\nrendering: dimensiondata_vlan\nrendering: dimensiondata_backup", "stdout_lines": ["PYTHONPATH=../lib ../hacking/module_formatter.py -t rst --template-dir=../hacking/templates --module-dir=../lib/ansible/modules -o rst/", "rendering: dimensiondata_vlan", "rendering: dimensiondata_backup"], "warnings": []}
```

The whole document generation process crashes because it wanted a list and you gave it a string.
See the next section for more info on things NOT to do.  Note: not all problems present themselves in such an obvious way.  Some just silently fail.  Neat.


### Documentation Issues in the Python Code

The Dimension Data python code contains specially-formatted text which is used to generate the documentation.  There are some issues with how to document your code that affect the generation of the README file.  These are covered below.

The “docstring” sections in the python code consists of the following sections: DOCUMENTATION, EXAMPLES and RETURN.  The DOCUMENTATION section has many picky rules; the other two sections, not as much.  Most of the issues below will be involved with fields found in the DOCUMENTATION section.

Note the following “definitions:”

string_field: field value is this text

list_field:
  - first line (note that the dash must be 2 spaces indented from the f in field_name above it)
  - optional 2nd and subsequent lines

choice_field: []

non_empty_choice_field: [value1, value2, … valueN]


The following fields seem to be strings:
  - module
  - short_description
  - version_added
  - required
  - default
 
The following fields seem to be lists:
  - description (at the module level)
  - description (at the per passed parameter level)

The following fields seem to be choices:
  - aliases
  - choices

Here are some issues/problems/bugs that I have run into:

* short_docstring is **required**.

* description is **required**.

* If you give a string value for a list field, you will receive an error.

* If you give a list for a string field, you may get an error.

* All lines must have some sort of leader
```
    For example, this works:
         description:
           - foo, foo, foo
           - bar, bar, bar

    However, this will fail:
         description:
           - foo, foo, foo
             bar, bar, bar

(note the lack of - )

```
* To show a value, do not surround the value with single quotes (i.e., ‘quoted’).
When you do this, it shows up as: [u```quoted` `` ]

* To show choices, use: [abc, def, chi, jklmnop ]

* The RETURNS section may not be required.

* Nested fields may not document well.  For example, one file has a return value which has an option that is defined as:
```
    contains:
        enabled:
            description: Rule state.
            type: string
            sample: true
        source:
            description: Source rule attributes.
            type: dictionary
            sample:
                any_ip:
                    description: Set if address is ANY.
                    type: string
                    sample: ANY
                port_end:
                    description: End port.
                    type: string
                    sample: null
        destination:
```

So this shows that the field source itself consists of any_ip and port_end.
This nested description does not document well. At the current time, it does not work.  Keep an eye out for this issue.






