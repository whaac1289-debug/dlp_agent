#include "content_extractor.h"

namespace dlp::extract {

std::string PdfExtractor::ExtractText(const std::string& path) {
    (void)path;
    return {};
}

std::string DocxExtractor::ExtractText(const std::string& path) {
    (void)path;
    return {};
}

std::string XlsxExtractor::ExtractText(const std::string& path) {
    (void)path;
    return {};
}

std::unique_ptr<ContentExtractor> CreateExtractorForExtension(const std::string& extension) {
    if (extension == ".pdf") {
        return std::make_unique<PdfExtractor>();
    }
    if (extension == ".docx") {
        return std::make_unique<DocxExtractor>();
    }
    if (extension == ".xlsx") {
        return std::make_unique<XlsxExtractor>();
    }
    return nullptr;
}

}  // namespace dlp::extract
