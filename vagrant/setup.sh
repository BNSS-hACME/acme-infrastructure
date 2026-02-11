#!/bin/bash

vagrant up
vagrant ssh-config > ../ansible/vagrant-ssh-config
