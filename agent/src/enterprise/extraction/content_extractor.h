#pragma once

#include <memory>
#include <string>

namespace dlp::extract {

class ContentExtractor {
public:
    virtual ~ContentExtractor() = default;
    virtual std::string ExtractText(const std::string& path) = 0;
};

class PdfExtractor : public ContentExtractor {
public:
    std::string ExtractText(const std::string& path) override;
};

class DocxExtractor : public ContentExtractor {
public:
    std::string ExtractText(const std::string& path) override;
};

class XlsxExtractor : public ContentExtractor {
public:
    std::string ExtractText(const std::string& path) override;
};

std::unique_ptr<ContentExtractor> CreateExtractorForExtension(const std::string& extension);

}  // namespace dlp::extract
