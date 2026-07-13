#!/bin/bash
docker build -t vulapp .
docker run -d -p 5000:5000 --name vulapp-container -v /var/run/docker.sock:/var/run/docker.sock vulapp
