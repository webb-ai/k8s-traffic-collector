#!/bin/bash

go build -o worker .

sudo ./worker --hub-ws-address ws://localhost:8898/wsTapper -i any
