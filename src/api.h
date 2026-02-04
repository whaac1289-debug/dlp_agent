#pragma once

#include <string>

void api_sender_thread();
void telemetry_enqueue(const std::string &type, const std::string &payload_json);
