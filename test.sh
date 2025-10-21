#!/bin/bash
set -e

# Run all tests
cargo test -- --test-threads=1 

# Run all ignored tests
cargo test -- --test-threads=1 --ignored