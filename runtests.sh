#!/bin/sh
docker run -it --rm \
    -v "${PWD}/docker/config:/config" \
    -v "${PWD}/docker/reports:/reports" \
    --network host \
    crossbario/autobahn-testsuite \
    wstest -m fuzzingclient -s /config/fuzzingclient.json
