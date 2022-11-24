#!/bin/bash

go build -o worker .

sudo ./worker --api-server-address ws://localhost:8898/wsTapper -i any
