#!/bin/bash

go build -o worker .

sudo ./worker --api-server-address ws://localhost:8899/wsTapper -i any
