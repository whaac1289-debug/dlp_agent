#include "pii_detector.h"
#include <algorithm>
#include <cctype>
#include <regex>

static bool luhn_check(const std::string &digits) {
    int sum = 0;
    bool alternate = false;
    for (auto it = digits.rbegin(); it != digits.rend(); ++it) {
        if (!std::isdigit(static_cast<unsigned char>(*it))) continue;
        int n = *it - '0';
        if (alternate) {
            n *= 2;
            if (n > 9) n -= 9;
        }
        sum += n;
        alternate = !alternate;
    }
    return sum % 10 == 0;
}

static bool iban_check(const std::string &iban) {
    std::string rearranged = iban.substr(4) + iban.substr(0, 4);
    int mod = 0;
    for (char c : rearranged) {
        if (std::isspace(static_cast<unsigned char>(c))) continue;
        if (std::isdigit(static_cast<unsigned char>(c))) {
            mod = (mod * 10 + (c - '0')) % 97;
        } else if (std::isalpha(static_cast<unsigned char>(c))) {
            int value = std::toupper(static_cast<unsigned char>(c)) - 'A' + 10;
            mod = (mod * 10 + (value / 10)) % 97;
            mod = (mod * 10 + (value % 10)) % 97;
        } else {
            return false;
        }
    }
    return mod == 1;
}

static std::string normalize_digits(const std::string &value) {
    std::string out;
    for (char c : value) {
        if (std::isdigit(static_cast<unsigned char>(c))) out.push_back(c);
    }
    return out;
}

static void add_matches(const std::regex &pattern,
                        const std::string &type,
                        const std::string &text,
                        std::vector<PiiDetection> &out) {
    for (auto it = std::sregex_iterator(text.begin(), text.end(), pattern);
         it != std::sregex_iterator(); ++it) {
        PiiDetection det;
        det.type = type;
        det.value = it->str();
        det.start = static_cast<size_t>(it->position());
        det.end = det.start + it->length();
        out.push_back(det);
    }
}

std::vector<PiiDetection> detect_pii(const std::string &text,
                                     const std::vector<std::string> &national_patterns) {
    std::vector<PiiDetection> out;
    if (text.empty()) return out;

    std::regex email_re(R"((?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b)");
    add_matches(email_re, "email", text, out);

    std::regex phone_re(R"(\b\+?[0-9][0-9()\-\.\s]{7,}[0-9]\b)");
    add_matches(phone_re, "phone", text, out);

    std::regex passport_re(R"(\b[A-Z]{1,2}[0-9]{6,9}\b)");
    add_matches(passport_re, "passport", text, out);

    std::regex iban_re(R"(\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b)");
    for (auto it = std::sregex_iterator(text.begin(), text.end(), iban_re);
         it != std::sregex_iterator(); ++it) {
        PiiDetection det;
        det.type = "iban";
        det.value = it->str();
        det.start = static_cast<size_t>(it->position());
        det.end = det.start + it->length();
        det.valid = iban_check(det.value);
        out.push_back(det);
    }

    std::regex cc_re(R"(\b(?:\d[ -]*?){13,19}\b)");
    for (auto it = std::sregex_iterator(text.begin(), text.end(), cc_re);
         it != std::sregex_iterator(); ++it) {
        PiiDetection det;
        det.type = "credit_card";
        det.value = it->str();
        det.start = static_cast<size_t>(it->position());
        det.end = det.start + it->length();
        std::string digits = normalize_digits(det.value);
        det.valid = digits.size() >= 13 && digits.size() <= 19 && luhn_check(digits);
        out.push_back(det);
    }

    for (const auto &pattern : national_patterns) {
        if (pattern.empty()) continue;
        try {
            std::regex national_re(pattern);
            add_matches(national_re, "national_id", text, out);
        } catch (const std::regex_error &) {
            continue;
        }
    }

    return out;
}
