#!/bin/bash 

/bin/ansible webservers -m archive -a"path=/var/www/html dest=/var/www/html/content.tar.gz"
/bin/ansible all -m archive -a"path=/var/log dest=/var/log/logs.tar.gz"

