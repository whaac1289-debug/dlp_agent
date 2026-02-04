Build a modular Windows 11 DLP endpoint agent in C++ that compiles with MSYS2 UCRT64 using make (g++).
The project must be production-style structured and fully compilable.

Requirements:

Create a project named dlp_agent with a Makefile and multiple C++ modules.

The agent must run as a long-running background process (service-style loop) and implement:

Core Features

USB Device Monitoring

Use WMI (Win32_DiskDrive InterfaceType='USB')

Detect insert/remove

Extract model and serial

Generate structured events

Device Control Policy

Write registry policies to:

disable USB storage

block removable devices

Support allowlist by serial (config file)

Policy module must be isolated

File Activity Monitoring

Use ReadDirectoryChangesW

Monitor:

USB drives (full)

Local user folders (filtered)

Filter by extension list

Ignore temp files

Emit events for create/write/delete/rename

Event Pipeline
Implement event pipeline:

event → normalize → filter → policy_check → enrich → queue → log → api_batch

SQLite Storage

Use sqlite3

Tables:

events

device_events

file_events

retry_queue

API Client

Use libcurl

JSON POST batch sender

Retry queue if server offline

Configurable server URL

Hash Module

SHA256 using Windows CNG (bcrypt)

Async-friendly interface

Logging

Thread-safe

File + sqlite dual logging

Config
Load config.json:

server_url

extension_filter

size_threshold

usb_allow_serials

Threading
Use worker threads for:

usb scan loop

file watchers

api sender

retry queue

Project Structure Required

Make Codex generate:

Makefile
main.cpp
service_loop.cpp
usb_scan.cpp/h
file_watch.cpp/h
policy.cpp/h
event_bus.cpp/h
filter.cpp/h
api.cpp/h
sqlite_store.cpp/h
log.cpp/h
hash.cpp/h
config.cpp/h

Build Constraints

Must compile with:

g++ -std=c++17
MSYS2 UCRT64
Link with:

lcURL

lsqlite3

lole32

loleaut32

lwbemuuid

lbcrypt

No Visual Studio only features.

Output Rules

All files fully written

No pseudo code

No TODO blocks

Must compile

Use Windows API correctly

Use UTF-8 safe conversions

Avoid third-party JSON libs (write minimal parser)