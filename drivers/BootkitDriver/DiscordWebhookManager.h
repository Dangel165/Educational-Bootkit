// DiscordWebhookManager.h: Discord webhook data exfiltration analysis component
// Educational security research component for analyzing Discord webhook communication techniques

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>
#include <ntstrsafe.h>
#include <windef.h>

#ifdef __cplusplus
#include <string>
#include <vector>
#include <memory>
#include <functional>

// Discord webhook message structure
typedef struct _DISCORD_MESSAGE {
    std::string content;
    std::string username;
    std::string avatar_url;
    bool tts;
    std::vector<std::string> embeds;
} DISCORD_MESSAGE, *PDISCORD_MESSAGE;

// Webhook response structure
typedef struct _WEBHOOK_RESPONSE {
    bool success;
    ULONG status_code;
    std::string response_body;
    ULONG64 response_time_ms;
    bool rate_limited;
    ULONG retry_after_ms;
    std::string error_message;
} WEBHOOK_RESPONSE, *PWEBHOOK_RESPONSE;

// Rate limiting analysis data
typedef struct _RATE_LIMIT_DATA {
    ULONG requests_per_minute;
    ULONG requests_per_hour;
    ULONG64 last_request_time;
    ULONG consecutive_failures;
    bool rate_limit_detected;
    ULONG rate_limit_window_ms;
    ULONG rate_limit_max_requests;
} RATE_LIMIT_DATA, *PRATE_LIMIT_DATA;

// Webhook URL validation result
typedef struct _WEBHOOK_VALIDATION {
    bool valid_format;
    bool valid_domain;
    bool valid_path;
    bool secure_protocol;
    std::string validation_errors;
    ULONG validation_score;
} WEBHOOK_VALIDATION, *PWEBHOOK_VALIDATION;

// Discord Webhook Manager class
class DiscordWebhookManager {
private:
    // Private member variables
    std::string m_webhook_url;
    RATE_LIMIT_DATA m_rate_limit_data;
    WEBHOOK_VALIDATION m_validation_result;
    bool m_ssl_enabled;
    bool m_debug_logging;
    
    // HTTP client components
    PVOID m_http_session;
    PVOID m_ssl_context;
    
    // Logging buffer
    CHAR m_log_buffer[4096];
    FAST_MUTEX m_log_mutex;
    
    // Private methods
    NTSTATUS InitializeHTTPClient();
    NTSTATUS CleanupHTTPClient();
    NTSTATUS ValidateWebhookURL(PWEBHOOK_VALIDATION validation);
    NTSTATUS AnalyzeRateLimiting(PRATE_LIMIT_DATA rate_data);
    NTSTATUS ConstructJSONPayload(PDISCORD_MESSAGE message, PCHAR buffer, ULONG buffer_size);
    NTSTATUS SendHTTPRequest(PCHAR url, PCHAR payload, ULONG payload_size, PWEBHOOK_RESPONSE response);
    NTSTATUS ParseHTTPResponse(PCHAR response_data, ULONG response_size, PWEBHOOK_RESPONSE parsed_response);
    VOID LogRequestResponse(PCHAR url, PWEBHOOK_RESPONSE response, ULONG64 request_time);
    
public:
    // Constructor and destructor
    DiscordWebhookManager();
    ~DiscordWebhookManager();
    
    // Public interface methods
    NTSTATUS Initialize(PCHAR webhook_url, bool enable_ssl = true, bool enable_debug = false);
    NTSTATUS Shutdown();
    
    NTSTATUS SendMessage(PDISCORD_MESSAGE message, PWEBHOOK_RESPONSE response);
    NTSTATUS SendEmbeddedMessage(PCHAR content, PCHAR title, PCHAR description, PCHAR color, PWEBHOOK_RESPONSE response);
    NTSTATUS SendFile(PCHAR file_path, PCHAR message_content, PWEBHOOK_RESPONSE response);
    
    NTSTATUS AnalyzeWebhookURL(PCHAR url, PWEBHOOK_VALIDATION validation);
    NTSTATUS AnalyzeRateLimitPatterns(PRATE_LIMIT_DATA rate_data);
    NTSTATUS TestWebhookCommunication(PCHAR test_url, PWEBHOOK_RESPONSE response);
    
    NTSTATUS EnableDebugLogging(bool enable);
    NTSTATUS GetRequestLog(PCHAR buffer, ULONG buffer_size);
    NTSTATUS ClearRequestLog();
    
    // Static utility methods
    static NTSTATUS IsValidDiscordWebhookURL(PCHAR url, bool* is_valid);
    static NTSTATUS ExtractWebhookComponents(PCHAR url, PCHAR webhook_id, ULONG id_size, PCHAR webhook_token, ULONG token_size);
    static NTSTATUS GenerateTestPayload(PCHAR buffer, ULONG buffer_size);
    static NTSTATUS SimulateRateLimitTest(PCHAR url, PRATE_LIMIT_DATA rate_data);
    
    // Educational analysis methods
    NTSTATUS AnalyzeExfiltrationPatterns(PCHAR captured_data, ULONG data_size, PWEBHOOK_RESPONSE analysis);
    NTSTATUS DemonstrateDataObfuscation(PCHAR original_data, ULONG data_size, PCHAR obfuscated_buffer, ULONG buffer_size);
    NTSTATUS TestEvasionTechniques(PCHAR url, PCHAR payload, ULONG payload_size, PWEBHOOK_RESPONSE response);
};

// C interface for kernel mode
#ifdef __cplusplus
extern "C" {
#endif

// C-compatible function declarations
NTSTATUS DiscordWebhookManager_Create(PVOID* manager_instance);
NTSTATUS DiscordWebhookManager_Destroy(PVOID manager_instance);
NTSTATUS DiscordWebhookManager_Initialize(PVOID manager_instance, PCHAR webhook_url, BOOLEAN enable_ssl);
NTSTATUS DiscordWebhookManager_SendMessage(PVOID manager_instance, PCHAR content, PCHAR username, PCHAR* response_buffer, ULONG buffer_size);
NTSTATUS DiscordWebhookManager_AnalyzeURL(PVOID manager_instance, PCHAR url, PCHAR validation_buffer, ULONG buffer_size);
NTSTATUS DiscordWebhookManager_TestCommunication(PVOID manager_instance, PCHAR test_url, PCHAR response_buffer, ULONG buffer_size);

#ifdef __cplusplus
}
#endif

#endif // __cplusplus