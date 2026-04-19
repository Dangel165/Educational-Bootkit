// DiscordWebhookTest.cpp: Test file for Discord webhook analysis system
// Educational security research test for analyzing Discord webhook communication techniques

#include <ntddk.h>
#include <wdm.h>
#include "drivers/BootkitDriver/DiscordWebhookManager.h"
#include "drivers/BootkitDriver/Debug.h"

extern "C" {

// Test function for Discord webhook URL validation
NTSTATUS TestDiscordWebhookValidation()
{
    DBG_PRINT("[DiscordWebhookTest] Testing Discord webhook URL validation\n");
    
    // Test URLs
    const char* valid_url = "https://discord.com/api/webhooks/123456789012345678/AbCdEfGhIjKlMnOpQrStUvWxYz1234567890";
    const char* invalid_url_http = "http://discord.com/api/webhooks/123456789012345678/AbCdEfGhIjKlMnOpQrStUvWxYz1234567890";
    const char* invalid_url_no_webhooks = "https://discord.com/api/something/123456789012345678/AbCdEfGhIjKlMnOpQrStUvWxYz1234567890";
    const char* invalid_domain = "https://evil.com/api/webhooks/123456789012345678/AbCdEfGhIjKlMnOpQrStUvWxYz1234567890";
    
    // Test static validation function
    bool is_valid = false;
    
    // Test 1: Valid URL
    NTSTATUS status = DiscordWebhookManager::IsValidDiscordWebhookURL(valid_url, &is_valid);
    if (NT_SUCCESS(status) && is_valid) {
        DBG_PRINT("[DiscordWebhookTest] Valid URL test PASSED\n");
    } else {
        DBG_PRINT("[DiscordWebhookTest] Valid URL test FAILED\n");
        return STATUS_UNSUCCESSFUL;
    }
    
    // Test 2: Invalid URL (HTTP instead of HTTPS)
    status = DiscordWebhookManager::IsValidDiscordWebhookURL(invalid_url_http, &is_valid);
    if (NT_SUCCESS(status) && !is_valid) {
        DBG_PRINT("[DiscordWebhookTest] HTTP URL test PASSED (correctly identified as invalid)\n");
    } else {
        DBG_PRINT("[DiscordWebhookTest] HTTP URL test FAILED\n");
        return STATUS_UNSUCCESSFUL;
    }
    
    // Test 3: Invalid URL (wrong path)
    status = DiscordWebhookManager::IsValidDiscordWebhookURL(invalid_url_no_webhooks, &is_valid);
    if (NT_SUCCESS(status) && !is_valid) {
        DBG_PRINT("[DiscordWebhookTest] Wrong path test PASSED (correctly identified as invalid)\n");
    } else {
        DBG_PRINT("[DiscordWebhookTest] Wrong path test FAILED\n");
        return STATUS_UNSUCCESSFUL;
    }
    
    // Test 4: Invalid URL (wrong domain)
    status = DiscordWebhookManager::IsValidDiscordWebhookURL(invalid_domain, &is_valid);
    if (NT_SUCCESS(status) && !is_valid) {
        DBG_PRINT("[DiscordWebhookTest] Wrong domain test PASSED (correctly identified as invalid)\n");
    } else {
        DBG_PRINT("[DiscordWebhookTest] Wrong domain test FAILED\n");
        return STATUS_UNSUCCESSFUL;
    }
    
    DBG_PRINT("[DiscordWebhookTest] All URL validation tests PASSED\n");
    return STATUS_SUCCESS;
}

// Test function for webhook component extraction
NTSTATUS TestWebhookComponentExtraction()
{
    DBG_PRINT("[DiscordWebhookTest] Testing webhook component extraction\n");
    
    const char* test_url = "https://discord.com/api/webhooks/123456789012345678/AbCdEfGhIjKlMnOpQrStUvWxYz1234567890";
    
    CHAR webhook_id[64] = {0};
    CHAR webhook_token[128] = {0};
    
    NTSTATUS status = DiscordWebhookManager::ExtractWebhookComponents(
        test_url,
        webhook_id,
        sizeof(webhook_id),
        webhook_token,
        sizeof(webhook_token)
    );
    
    if (NT_SUCCESS(status)) {
        DBG_PRINT("[DiscordWebhookTest] Extracted ID: %s\n", webhook_id);
        DBG_PRINT("[DiscordWebhookTest] Extracted Token: %s\n", webhook_token);
        
        if (strcmp(webhook_id, "123456789012345678") == 0 &&
            strcmp(webhook_token, "AbCdEfGhIjKlMnOpQrStUvWxYz1234567890") == 0) {
            DBG_PRINT("[DiscordWebhookTest] Component extraction test PASSED\n");
            return STATUS_SUCCESS;
        }
    }
    
    DBG_PRINT("[DiscordWebhookTest] Component extraction test FAILED\n");
    return STATUS_UNSUCCESSFUL;
}

// Test function for DiscordWebhookManager class
NTSTATUS TestDiscordWebhookManagerClass()
{
    DBG_PRINT("[DiscordWebhookTest] Testing DiscordWebhookManager class\n");
    
    // Create manager instance
    DiscordWebhookManager* manager = nullptr;
    try {
        manager = new DiscordWebhookManager();
    }
    catch (...) {
        DBG_PRINT("[DiscordWebhookTest] Failed to create manager instance\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    if (!manager) {
        DBG_PRINT("[DiscordWebhookTest] Manager instance is null\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // Test URL (educational/test URL - not real)
    const char* test_webhook_url = "https://discord.com/api/webhooks/test/educational";
    
    // Initialize manager
    NTSTATUS status = manager->Initialize(test_webhook_url, true, true);
    if (!NT_SUCCESS(status)) {
        DBG_PRINT("[DiscordWebhookTest] Manager initialization failed: 0x%08X\n", status);
        delete manager;
        return status;
    }
    
    // Test 1: Send test message
    DBG_PRINT("[DiscordWebhookTest] Testing message sending\n");
    
    DiscordWebhookManager::DISCORD_MESSAGE message;
    message.content = "Educational test message from Bootkit Analysis Framework";
    message.username = "SecurityResearchBot";
    message.tts = false;
    
    DiscordWebhookManager::WEBHOOK_RESPONSE response;
    status = manager->SendMessage(&message, &response);
    
    if (NT_SUCCESS(status)) {
        DBG_PRINT("[DiscordWebhookTest] Message sending test PASSED\n");
        DBG_PRINT("[DiscordWebhookTest] Response - Success: %s, Status: %lu, Time: %llu ms\n",
                  response.success ? "true" : "false",
                  response.status_code,
                  response.response_time_ms);
    } else {
        DBG_PRINT("[DiscordWebhookTest] Message sending test FAILED: 0x%08X\n", status);
        manager->Shutdown();
        delete manager;
        return status;
    }
    
    // Test 2: Test rate limiting analysis
    DBG_PRINT("[DiscordWebhookTest] Testing rate limiting analysis\n");
    
    DiscordWebhookManager::RATE_LIMIT_DATA rate_data;
    status = manager->AnalyzeRateLimitPatterns(&rate_data);
    
    if (NT_SUCCESS(status)) {
        DBG_PRINT("[DiscordWebhookTest] Rate limiting analysis test PASSED\n");
        DBG_PRINT("[DiscordWebhookTest] Requests/min: %lu, Rate Limited: %s\n",
                  rate_data.requests_per_minute,
                  rate_data.rate_limit_detected ? "true" : "false");
    } else {
        DBG_PRINT("[DiscordWebhookTest] Rate limiting analysis test FAILED: 0x%08X\n", status);
    }
    
    // Test 3: Test URL analysis
    DBG_PRINT("[DiscordWebhookTest] Testing URL analysis\n");
    
    DiscordWebhookManager::WEBHOOK_VALIDATION validation;
    status = manager->AnalyzeWebhookURL(test_webhook_url, &validation);
    
    if (NT_SUCCESS(status)) {
        DBG_PRINT("[DiscordWebhookTest] URL analysis test PASSED\n");
        DBG_PRINT("[DiscordWebhookTest] Validation Score: %lu, Valid Format: %s\n",
                  validation.validation_score,
                  validation.valid_format ? "true" : "false");
    } else {
        DBG_PRINT("[DiscordWebhookTest] URL analysis test FAILED: 0x%08X\n", status);
    }
    
    // Test 4: Test payload generation
    DBG_PRINT("[DiscordWebhookTest] Testing payload generation\n");
    
    CHAR test_payload[1024] = {0};
    status = DiscordWebhookManager::GenerateTestPayload(test_payload, sizeof(test_payload));
    
    if (NT_SUCCESS(status)) {
        DBG_PRINT("[DiscordWebhookTest] Payload generation test PASSED\n");
        DBG_PRINT("[DiscordWebhookTest] Generated payload (first 100 chars): %.100s\n", test_payload);
    } else {
        DBG_PRINT("[DiscordWebhookTest] Payload generation test FAILED: 0x%08X\n", status);
    }
    
    // Test 5: Test exfiltration pattern analysis
    DBG_PRINT("[DiscordWebhookTest] Testing exfiltration pattern analysis\n");
    
    const char* test_data = "Sample data for exfiltration analysis";
    DiscordWebhookManager::WEBHOOK_RESPONSE exfiltration_analysis;
    status = manager->AnalyzeExfiltrationPatterns(test_data, strlen(test_data), &exfiltration_analysis);
    
    if (NT_SUCCESS(status)) {
        DBG_PRINT("[DiscordWebhookTest] Exfiltration pattern analysis test PASSED\n");
    } else {
        DBG_PRINT("[DiscordWebhookTest] Exfiltration pattern analysis test FAILED: 0x%08X\n", status);
    }
    
    // Cleanup
    manager->Shutdown();
    delete manager;
    
    DBG_PRINT("[DiscordWebhookTest] All DiscordWebhookManager tests completed\n");
    return STATUS_SUCCESS;
}

// Test function for data obfuscation demonstration
NTSTATUS TestDataObfuscation()
{
    DBG_PRINT("[DiscordWebhookTest] Testing data obfuscation demonstration\n");
    
    const char* original_data = "This is sensitive data that needs obfuscation";
    ULONG data_size = strlen(original_data);
    
    CHAR obfuscated_buffer[256] = {0};
    
    NTSTATUS status = DiscordWebhookManager::DemonstrateDataObfuscation(
        original_data,
        data_size,
        obfuscated_buffer,
        sizeof(obfuscated_buffer)
    );
    
    if (NT_SUCCESS(status)) {
        DBG_PRINT("[DiscordWebhookTest] Data obfuscation test PASSED\n");
        DBG_PRINT("[DiscordWebhookTest] Original: %s\n", original_data);
        DBG_PRINT("[DiscordWebhookTest] Obfuscated (hex): ");
        for (ULONG i = 0; i < data_size && i < 20; i++) {
            DBG_PRINT("%02X ", (unsigned char)obfuscated_buffer[i]);
        }
        DBG_PRINT("\n");
    } else {
        DBG_PRINT("[DiscordWebhookTest] Data obfuscation test FAILED: 0x%08X\n", status);
        return status;
    }
    
    return STATUS_SUCCESS;
}

// Test function for rate limit simulation
NTSTATUS TestRateLimitSimulation()
{
    DBG_PRINT("[DiscordWebhookTest] Testing rate limit simulation\n");
    
    const char* test_url = "https://discord.com/api/webhooks/test/rate_limit_test";
    
    DiscordWebhookManager::RATE_LIMIT_DATA rate_data;
    NTSTATUS status = DiscordWebhookManager::SimulateRateLimitTest(test_url, &rate_data);
    
    if (NT_SUCCESS(status)) {
        DBG_PRINT("[DiscordWebhookTest] Rate limit simulation test PASSED\n");
        DBG_PRINT("[DiscordWebhookTest] Requests/min: %lu, Rate Limited: %s, Window: %lu ms\n",
                  rate_data.requests_per_minute,
                  rate_data.rate_limit_detected ? "true" : "false",
                  rate_data.rate_limit_window_ms);
    } else {
        DBG_PRINT("[DiscordWebhookTest] Rate limit simulation test FAILED: 0x%08X\n", status);
        return status;
    }
    
    return STATUS_SUCCESS;
}

// Main test function
NTSTATUS RunDiscordWebhookTests()
{
    DBG_PRINT("[DiscordWebhookTest] ========================================\n");
    DBG_PRINT("[DiscordWebhookTest] Starting Discord Webhook Analysis Tests\n");
    DBG_PRINT("[DiscordWebhookTest] ========================================\n");
    
    NTSTATUS final_status = STATUS_SUCCESS;
    NTSTATUS test_status;
    
    // Run individual tests
    test_status = TestDiscordWebhookValidation();
    if (!NT_SUCCESS(test_status)) {
        DBG_PRINT("[DiscordWebhookTest] URL validation test FAILED\n");
        final_status = test_status;
    }
    
    test_status = TestWebhookComponentExtraction();
    if (!NT_SUCCESS(test_status)) {
        DBG_PRINT("[DiscordWebhookTest] Component extraction test FAILED\n");
        final_status = test_status;
    }
    
    test_status = TestDiscordWebhookManagerClass();
    if (!NT_SUCCESS(test_status)) {
        DBG_PRINT("[DiscordWebhookTest] Manager class test FAILED\n");
        final_status = test_status;
    }
    
    test_status = TestDataObfuscation();
    if (!NT_SUCCESS(test_status)) {
        DBG_PRINT("[DiscordWebhookTest] Data obfuscation test FAILED\n");
        final_status = test_status;
    }
    
    test_status = TestRateLimitSimulation();
    if (!NT_SUCCESS(test_status)) {
        DBG_PRINT("[DiscordWebhookTest] Rate limit simulation test FAILED\n");
        final_status = test_status;
    }
    
    DBG_PRINT("[DiscordWebhookTest] ========================================\n");
    if (NT_SUCCESS(final_status)) {
        DBG_PRINT("[DiscordWebhookTest] ALL TESTS PASSED\n");
    } else {
        DBG_PRINT("[DiscordWebhookTest] SOME TESTS FAILED: 0x%08X\n", final_status);
    }
    DBG_PRINT("[DiscordWebhookTest] ========================================\n");
    
    return final_status;
}

// Driver entry point for testing
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);
    
    DBG_PRINT("[DiscordWebhookTest] Driver entry point for testing\n");
    
    // Run Discord webhook tests
    NTSTATUS status = RunDiscordWebhookTests();
    
    DBG_PRINT("[DiscordWebhookTest] Test execution completed with status: 0x%08X\n", status);
    
    return status;
}

} // extern "C"