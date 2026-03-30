# CSCE 3550 - Project 2 - tal0174

## JWKS Server with SQLite + JWT Authentication

This project is a RESTful JWKS server written in C++. It issues RS256-signed JWTs and stores signing keys in a SQLite database. The server supports both valid and expired tokens and exposes a JWKS endpoint that only returns active keys.

---

## Features

- Generates RS256 signed JWTs
- Can generate expired JWTs for testing
- JWKS endpoint filters out expired keys
- Uses SQLite database (`totally_not_my_privateKeys.db`) to store keys
- Uses prepared SQL statements (prevents SQL injection)
- Correct HTTP behavior (ex: GET /auth returns 405)
- Includes a Python test suite
- Test coverage is above 80%

---

## Build Instructions

Compile normally:

g++ jwks.cpp -o jwks -std=c++17 -lssl -lcrypto -lsqlite3

Compile with coverage:

g++ jwks.cpp -o jwks -std=c++17 --coverage -lssl -lcrypto -lsqlite3

---

## Running the Server

./jwks

Server runs on:

http://localhost:8080

---

## Endpoints

### GET /
Basic health check to confirm the server is running

### GET /.well-known/jwks.json
Returns all valid (non-expired) public keys

### POST /auth
Returns a valid JWT

### POST /auth?expired=true
Returns an expired JWT

### GET /auth
Returns 405 Method Not Allowed

---

## Running Tests

python3 test_jwks.py

Tests check:
- JWT structure and fields
- Expired vs valid tokens
- JWKS key filtering
- Proper HTTP responses

---

## Test Coverage

gcov jwks.cpp

Result:

Lines executed: 82.72%

This meets the requirement of at least 80% coverage.

---

## Database

The project uses a SQLite database:

totally_not_my_privateKeys.db

This database stores the RSA private keys used to sign JWTs.  
Keys are automatically created (seeded) if the database is empty.

---

## Project Files

- jwks.cpp → main server implementation  
- sqlite3.c / sqlite3.h → SQLite library  
- httplib.h → HTTP server  
- json.hpp → JSON handling  
- test_jwks.py → test suite  
- totally_not_my_privateKeys.db → database file  

---

## Code Quality

The code is organized and separated by functionality.  
Prepared statements are used for database queries to avoid SQL injection.  
Comments are included where needed to explain logic.

---

## Screenshots

Screenshots are included in the repo showing:
- Server running
- Endpoint responses
- Test results
- Coverage output

---

## Final Status

- All required features implemented  
- All tests passing  
- Coverage above 80%  
- Project is complete and ready to submit  
