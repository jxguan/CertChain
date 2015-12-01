#!/bin/bash

printf "Resetting nodes..."

rm data_dir/hashchain.dat
rm data_dirs/node*/hashchain.dat
printf "Removed hashchains."

rm data_dir/documents/*
rm data_dirs/node*/documents/*
printf "Removed documents."

rm data_dir/replicas/*
rm data_dirs/node*/replicas/*
printf "Removed replicas."
