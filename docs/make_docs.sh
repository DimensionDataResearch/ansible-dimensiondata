#!/bin/sh

path=$1
ansible_webdocs=$2
output_file=$3

if [ "$#" -eq 3 ] || [ "$#" -eq 0 ] 
then
    if [ "$#" -eq "0" ] 
    then
        # typical paths
        path=../../ansible-dimensiondata/ansible/dimensiondata/
        ansible_webdocs_library=./ansible-webdocs/library
        output_file=../../ansible-dimensiondata/docs/README_DD_api.md
    fi
    # run the playbook with the passed params
    ansible-playbook make_ansible_docs_playbook.yml --module-path=$ansible_webdocs_library --extra-vars "code_path=$path ansible_webdocs=$ansible_webdocs_library output_file=$output_file -M $path"
    
else
    echo " "
    echo "Illegal number of parameters!"
    echo " "
    echo "Usage: $0 code_path ansible_webdocs output_file"
    echo "where:"
    echo "      code_path       = path to the directory contains the ansible source code"
    echo "      ansible_webdocs = path to the ansible-webdocs top level dir"
    echo "      output_file     = full path to the single output markdown file"
    echo " "
    exit 1
fi

