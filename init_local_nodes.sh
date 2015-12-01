#!/bin/bash

mkdir -p data_dirs/nodeA/replicas
mkdir -p data_dirs/nodeB/replicas
mkdir -p data_dirs/nodeA/documents
mkdir -p data_dirs/nodeB/documents

echo "[
  {
    \"inst_addr\": \"cmimxJwctxp6XCcQCN9stQVWbwonsh2zhF\",
    \"hostname\": \"stanford\",
    \"port\": 5000,
    \"our_peering_approval\": {
      \"NotApproved\": []
    }
  }
]" > data_dirs/nodeA/nodes.dat

echo "[
  {
    \"inst_addr\": \"cTAU63Kr2496gRkrW8irGpFum2LACmwCEP\",
    \"hostname\": \"virginia\",
    \"port\": 4000,
    \"our_peering_approval\": {
      \"NotApproved\": []
    }
  }
]" > data_dirs/nodeB/nodes.dat
