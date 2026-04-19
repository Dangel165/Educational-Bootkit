// SystemCallAnalyzer.h: System Call and IRP Pattern Analyzer for Task 3.1
// Implements system call frequency detection, IRP pattern analysis, and behavioral analysis
// with machine learning integration for anomalous pattern detection

#pragma once

#include "pch.h"
#include "ModernCpp.h"
#include "MemoryManagement.h"
#include "Concurrency.h"
#include "IrpMonitor.h"
#include "KernelHookFramework.h"

namespace BootkitFramework {

// Performance counter types for system call monitoring
enum class PerformanceCounterType {
    SystemCallFrequency,
    IRPCompletionTime,
    KernelAPICallRate,
    MemoryAllocationRate,
    ContextSwitchRate,
    InterruptRate,
    PageFaultRate,
    DiskIORate,
    NetworkIORate,
    RegistryAccessRate,
    FileAccessRate,
    ProcessCreationRate,
    ThreadCreationRate,
    HandleCreationRate,
    SecurityEventRate,
    Unknown
};

// Statistical model types
enum class StatisticalModelType {
    MovingAverage,
    ExponentialSmoothing,
    ARIMA,
    SeasonalDecomposition,
    AnomalyDetection,
    PatternRecognition,
    TrendAnalysis,
    CorrelationAnalysis,
    RegressionAnalysis,
    TimeSeriesForecasting,
    Unknown
};

// Machine learning algorithm types
enum class MLAlgorithmType {
    DecisionTree,
    RandomForest,
    GradientBoosting,
    NeuralNetwork,
    SupportVectorMachine,
    KMeansClustering,
    DBSCAN,
    IsolationForest,
    OneClassSVM,
    AutoEncoder,
    LSTM,
    GRU,
    Unknown
};

// Pattern analysis result
struct PatternAnalysisResult {
    BOOLEAN IsAnomalous;
    DOUBLE AnomalyScore;
    DOUBLE ConfidenceLevel;
    CHAR PatternType[32];
    CHAR Description[128];
    LARGE_INTEGER DetectionTime;
    ULONG PatternID;
    ULONG SeverityLevel;
    DOUBLE StatisticalSignificance;
    CHAR RecommendedAction[64];
};

// System call statistics
struct SystemCallStatistics {
    ULONG64 TotalSystemCalls;
    ULONG64 SystemCallsPerSecond;
    ULONG64 PeakSystemCallsPerSecond;
    ULONG64 AverageSystemCallsPerSecond;
    ULONG64 SystemCallTypes[32];  // Count by system call type
    DOUBLE SystemCallDistribution[32];  // Percentage distribution
    LARGE_INTEGER MonitoringStartTime;
    LARGE_INTEGER LastUpdateTime;
    ULONG64 MonitoringDurationSeconds;
    DOUBLE SystemCallEntropy;  // Information entropy of system call distribution
    DOUBLE SystemCallVariance;  // Statistical variance
    DOUBLE SystemCallSkewness;  // Statistical skewness
    DOUBLE SystemCallKurtosis;  // Statistical kurtosis
};

// IRP pattern statistics
struct IRPPatternStatistics {
    ULONG64 TotalIRPs;
    ULONG64 IRPsPerSecond;
    ULONG64 CompletedIRPs;
    ULONG64 PendingIRPs;
    ULONG64 FailedIRPs;
    ULONG64 IRPByMajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];
    ULONG64 IRPByMinorFunction[256];  // Common minor functions
    DOUBLE AverageCompletionTime;  // In 100-nanosecond units
    DOUBLE MaxCompletionTime;
    DOUBLE MinCompletionTime;
    DOUBLE CompletionTimeStdDev;
    ULONG64 IRPChainLengths[32];  // Distribution of IRP chain lengths
    DOUBLE IRPChainEntropy;
    ULONG64 IRPStackLocations;
    ULONG64 IRPReuseCount;
    DOUBLE IRPReuseRate;
};

// Kernel API usage pattern
struct KernelAPIPattern {
    CHAR APIName[64];
    CHAR ModuleName[32];
    PVOID APIAddress;
    ULONG64 CallCount;
    ULONG64 CallFrequency;  // Calls per second
    DOUBLE AverageExecutionTime;
    DOUBLE MaxExecutionTime;
    DOUBLE MinExecutionTime;
    DOUBLE ExecutionTimeStdDev;
    ULONG CallerDistribution[16];  // Distribution of caller types
    BOOLEAN IsHooked;
    BOOLEAN IsSuspicious;
    DOUBLE SuspicionScore;
    CHAR PatternSignature[128];
    LARGE_INTEGER FirstCallTime;
    LARGE_INTEGER LastCallTime;
};

// Performance counter data
struct PerformanceCounterData {
    PerformanceCounterType CounterType;
    CHAR CounterName[64];
    ULONG64 CounterValue;
    ULONG64 PreviousValue;
    ULONG64 DeltaValue;
    DOUBLE RatePerSecond;
    DOUBLE MovingAverage;
    DOUBLE ExponentialSmoothing;
    LARGE_INTEGER LastUpdateTime;
    ULONG UpdateInterval;  // In milliseconds
    BOOLEAN IsActive;
    BOOLEAN IsAnomalous;
    DOUBLE AnomalyScore;
};

// Statistical model configuration
struct StatisticalModelConfig {
    StatisticalModelType ModelType;
    CHAR ModelName[64];
    ULONG WindowSize;  // For moving average, etc.
    DOUBLE Alpha;      // For exponential smoothing
    DOUBLE Beta;       // For trend smoothing
    DOUBLE Gamma;      // For seasonal smoothing
    ULONG SeasonalPeriod;
    DOUBLE ThresholdMultiplier;  // For anomaly detection
    BOOLEAN IsTrained;
    ULONG TrainingSamples;
    DOUBLE ModelAccuracy;
    CHAR ModelFilePath[256];
};

// Machine learning model configuration
struct MLModelConfig {
    MLAlgorithmType AlgorithmType;
    CHAR ModelName[64];
    ULONG InputFeatures;
    ULONG OutputClasses;
    ULONG HiddenLayers;
    ULONG NeuronsPerLayer[16];
    DOUBLE LearningRate;
    ULONG TrainingEpochs;
    DOUBLE ValidationSplit;
    BOOLEAN IsTrained;
    ULONG TrainingSamples;
    DOUBLE ModelAccuracy;
    DOUBLE ModelPrecision;
    DOUBLE ModelRecall;
    DOUBLE ModelF1Score;
    CHAR ModelFilePath[256];
    CHAR FeatureNames[256][32];  // Up to 256 features, 32 chars each
};

// Behavioral analysis context
struct BehavioralAnalysisContext {
    KernelMutex AnalysisLock;
    BOOLEAN IsInitialized;
    BOOLEAN IsMonitoringActive;
    ULONG AnalysisInterval;  // In milliseconds
    
    // Performance counters
    PerformanceCounterData PerformanceCounters[32];
    ULONG PerformanceCounterCount;
    
    // Statistical models
    StatisticalModelConfig StatisticalModels[16];
    ULONG StatisticalModelCount;
    
    // Machine learning models
    MLModelConfig MLModels[8];
    ULONG MLModelCount;
    
    // Pattern storage
    KernelList<PatternAnalysisResult*> DetectedPatterns;
    ULONG PatternCount;
    
    // Alert system
    KernelList<PatternAnalysisResult*> ActiveAlerts;
    ULONG AlertCount;
    ULONG MaxAlerts;
    
    // Reporting
    CHAR ReportBuffer[4096];
    ULONG ReportBufferSize;
    BOOLEAN ReportPending;
    
    // Integration with other components
    PVOID IrpMonitorContext;
    PVOID HookManagerContext;
    PVOID SystemCallMonitorContext;
};

// System call and IRP pattern analyzer class
class SystemCallPatternAnalyzer {
private:
    BehavioralAnalysisContext m_Context;
    KernelUniquePtr<KernelHookManager> m_HookManager;
    
    // Internal methods
    NTSTATUS InternalInitializePerformanceCounters();
    NTSTATUS InternalInitializeStatisticalModels();
    NTSTATUS InternalInitializeMLModels();
    NTSTATUS InternalUpdatePerformanceCounters();
    NTSTATUS InternalAnalyzeSystemCallPatterns();
    NTSTATUS InternalAnalyzeIRPPatterns();
    NTSTATUS InternalAnalyzeKernelAPIPatterns();
    NTSTATUS InternalDetectAnomalies();
    NTSTATUS InternalGenerateAlerts();
    NTSTATUS InternalUpdateStatisticalModels();
    NTSTATUS InternalUpdateMLModels();
    NTSTATUS InternalTrainMLModels();
    NTSTATUS InternalGenerateReport();
    
    // Performance counter methods
    NTSTATUS InternalQuerySystemCallFrequency(_Out_ PerformanceCounterData* CounterData);
    NTSTATUS InternalQueryIRPCompletionTime(_Out_ PerformanceCounterData* CounterData);
    NTSTATUS InternalQueryKernelAPICallRate(_Out_ PerformanceCounterData* CounterData);
    NTSTATUS InternalQueryMemoryAllocationRate(_Out_ PerformanceCounterData* CounterData);
    NTSTATUS InternalQueryContextSwitchRate(_Out_ PerformanceCounterData* CounterData);
    
    // Statistical analysis methods
    NTSTATUS InternalCalculateMovingAverage(_In_ const DOUBLE* Data, _In_ ULONG DataSize, _In_ ULONG WindowSize, _Out_ DOUBLE* MovingAverage);
    NTSTATUS InternalCalculateExponentialSmoothing(_In_ const DOUBLE* Data, _In_ ULONG DataSize, _In_ DOUBLE Alpha, _Out_ DOUBLE* SmoothedData);
    NTSTATUS InternalDetectStatisticalAnomalies(_In_ const DOUBLE* Data, _In_ ULONG DataSize, _In_ DOUBLE ThresholdMultiplier, _Out_ BOOLEAN* IsAnomalous, _Out_ DOUBLE* AnomalyScore);
    NTSTATUS InternalCalculateCorrelation(_In_ const DOUBLE* Data1, _In_ const DOUBLE* Data2, _In_ ULONG DataSize, _Out_ DOUBLE* CorrelationCoefficient);
    
    // Machine learning methods
    NTSTATUS InternalTrainDecisionTree(_In_ const DOUBLE* TrainingData, _In_ ULONG Samples, _In_ ULONG Features, _In_ const ULONG* Labels, _Out_ MLModelConfig* ModelConfig);
    NTSTATUS InternalTrainIsolationForest(_In_ const DOUBLE* TrainingData, _In_ ULONG Samples, _In_ ULONG Features, _Out_ MLModelConfig* ModelConfig);
    NTSTATUS InternalPredictWithMLModel(_In_ const MLModelConfig* ModelConfig, _In_ const DOUBLE* InputFeatures, _Out_ DOUBLE* PredictionScore);
    
    // Pattern recognition methods
    NTSTATUS InternalRecognizeSystemCallPattern(_In_ const SystemCallStatistics* Stats, _Out_ PatternAnalysisResult* PatternResult);
    NTSTATUS InternalRecognizeIRPPattern(_In_ const IRPPatternStatistics* Stats, _Out_ PatternAnalysisResult* PatternResult);
    NTSTATUS InternalRecognizeKernelAPIPattern(_In_ const KernelAPIPattern* Pattern, _Out_ PatternAnalysisResult* PatternResult);
    
    // Alert management methods
    NTSTATUS InternalCreateAlert(_In_ const PatternAnalysisResult* PatternResult);
    NTSTATUS InternalClearAlert(_In_ ULONG PatternID);
    NTSTATUS InternalEscalateAlert(_In_ ULONG PatternID);
    NTSTATUS InternalSuppressAlert(_In_ ULONG PatternID);
    
public:
    SystemCallPatternAnalyzer();
    ~SystemCallPatternAnalyzer();
    
    // Initialization and cleanup
    NTSTATUS Initialize(_In_ ULONG AnalysisInterval = 1000, _In_ ULONG MaxAlerts = 100);
    NTSTATUS Cleanup();
    
    // Monitoring control
    NTSTATUS StartMonitoring();
    NTSTATUS StopMonitoring();
    NTSTATUS PauseMonitoring();
    NTSTATUS ResumeMonitoring();
    
    // Data collection and analysis
    NTSTATUS CollectSystemCallData(_Out_ SystemCallStatistics* Stats);
    NTSTATUS CollectIRPData(_Out_ IRPPatternStatistics* Stats);
    NTSTATUS CollectKernelAPIData(_Out_ KernelList<KernelAPIPattern*>* Patterns);
    NTSTATUS PerformPatternAnalysis();
    NTSTATUS PerformRealTimeAnalysis();
    
    // Statistical analysis
    NTSTATUS CalculateStatistics(_In_ const DOUBLE* Data, _In_ ULONG DataSize, 
                                 _Out_ DOUBLE* Mean, _Out_ DOUBLE* Variance, 
                                 _Out_ DOUBLE* StdDev, _Out_ DOUBLE* Skewness, 
                                 _Out_ DOUBLE* Kurtosis);
    NTSTATUS PerformTimeSeriesAnalysis(_In_ const DOUBLE* TimeSeriesData, _In_ ULONG DataSize, 
                                       _Out_ DOUBLE* Trend, _Out_ DOUBLE* Seasonality, 
                                       _Out_ DOUBLE* Residual);
    NTSTATUS DetectOutliers(_In_ const DOUBLE* Data, _In_ ULONG DataSize, 
                            _In_ DOUBLE Threshold, _Out_ ULONG* OutlierCount, 
                            _Out_ ULONG* OutlierIndices, _In_ ULONG MaxOutliers);
    
    // Machine learning operations
    NTSTATUS TrainAnomalyDetectionModel(_In_ const DOUBLE* TrainingData, _In_ ULONG Samples, _In_ ULONG Features);
    NTSTATUS TrainPatternRecognitionModel(_In_ const DOUBLE* TrainingData, _In_ ULONG Samples, _In_ ULONG Features, _In_ const ULONG* Labels);
    NTSTATUS PredictAnomaly(_In_ const DOUBLE* InputFeatures, _In_ ULONG FeatureCount, _Out_ DOUBLE* AnomalyScore);
    NTSTATUS ClassifyPattern(_In_ const DOUBLE* InputFeatures, _In_ ULONG FeatureCount, _Out_ ULONG* PatternClass);
    
    // Alert management
    NTSTATUS GetActiveAlerts(_Out_ KernelList<PatternAnalysisResult*>* Alerts);
    NTSTATUS GetAlertHistory(_In_ ULONG MaxAlerts, _Out_ KernelList<PatternAnalysisResult*>* AlertHistory);
    NTSTATUS ClearAllAlerts();
    NTSTATUS SetAlertThreshold(_In_ DOUBLE Threshold);
    NTSTATUS SetAlertSeverityFilter(_In_ ULONG MinSeverity);
    
    // Reporting
    NTSTATUS GenerateAnalysisReport(_Out_ PCHAR ReportBuffer, _In_ ULONG BufferSize, _Out_ PULONG BytesWritten);
    NTSTATUS GenerateDetailedReport(_In_ ULONG PatternID, _Out_ PCHAR ReportBuffer, _In_ ULONG BufferSize, _Out_ PULONG BytesWritten);
    NTSTATUS ExportReportToFile(_In_ PCSTR FilePath);
    NTSTATUS ExportDataToCSV(_In_ PCSTR FilePath);
    
    // Integration with other components
    NTSTATUS IntegrateWithIrpMonitor(_In_ PVOID IrpMonitorContext);
    NTSTATUS IntegrateWithHookManager(_In_ PVOID HookManagerContext);
    NTSTATUS IntegrateWithSystemCallMonitor(_In_ PVOID SystemCallMonitorContext);
    
    // Configuration
    NTSTATUS SetAnalysisInterval(_In_ ULONG IntervalMs);
    NTSTATUS SetPerformanceCounterTypes(_In_ const PerformanceCounterType* CounterTypes, _In_ ULONG Count);
    NTSTATUS SetStatisticalModelTypes(_In_ const StatisticalModelType* ModelTypes, _In_ ULONG Count);
    NTSTATUS SetMLAlgorithmTypes(_In_ const MLAlgorithmType* AlgorithmTypes, _In_ ULONG Count);
    
    // Status and diagnostics
    NTSTATUS GetAnalyzerStatus(_Out_ PBOOLEAN IsActive, _Out_ PULONG PatternCount, _Out_ PULONG AlertCount);
    NTSTATUS GetPerformanceCounterStatus(_Out_ PerformanceCounterData* Counters, _In_ ULONG MaxCounters, _Out_ PULONG CounterCount);
    NTSTATUS GetModelStatus(_Out_ StatisticalModelConfig* Models, _In_ ULONG MaxModels, _Out_ PULONG ModelCount);
    NTSTATUS ResetStatistics();
    NTSTATUS ResetModels();
    
    // Real-time alert callback
    typedef NTSTATUS (*ALERT_CALLBACK)(
        _In_ const PatternAnalysisResult* Alert,
        _In_ PVOID Context
    );
    
    NTSTATUS RegisterAlertCallback(_In_ ALERT_CALLBACK Callback, _In_ PVOID Context);
    NTSTATUS UnregisterAlertCallback();
};

// Global analyzer instance
extern KernelUniquePtr<SystemCallPatternAnalyzer> g_SystemCallAnalyzer;

// Utility functions for pattern analysis
NTSTATUS InitializeSystemCallAnalysis();
NTSTATUS CleanupSystemCallAnalysis();
NTSTATUS StartSystemCallMonitoring();
NTSTATUS StopSystemCallMonitoring();
NTSTATUS GetSystemCallAnalysisReport(_Out_ PCHAR Buffer, _In_ ULONG BufferSize, _Out_ PULONG BytesWritten);

// Performance counter utilities
NTSTATUS QueryPerformanceCounterValue(_In_ PerformanceCounterType CounterType, _Out_ ULONG64* CounterValue);
NTSTATUS CalculatePerformanceCounterRate(_In_ PerformanceCounterType CounterType, _Out_ DOUBLE* RatePerSecond);
NTSTATUS ResetPerformanceCounter(_In_ PerformanceCounterType CounterType);

// Statistical analysis utilities
NTSTATUS CalculateStatisticalMetrics(_In_ const DOUBLE* Data, _In_ ULONG DataSize, 
                                     _Out_ DOUBLE* Mean, _Out_ DOUBLE* Median, 
                                     _Out_ DOUBLE* Mode, _Out_ DOUBLE* Variance, 
                                     _Out_ DOUBLE* StdDev);
NTSTATUS DetectStatisticalAnomalies(_In_ const DOUBLE* Data, _In_ ULONG DataSize, 
                                    _In_ DOUBLE SigmaThreshold, _Out_ BOOLEAN* HasAnomalies, 
                                    _Out_ ULONG* AnomalyCount, _Out_ ULONG* AnomalyIndices, 
                                    _In_ ULONG MaxAnomalies);

// Pattern recognition utilities
NTSTATUS RecognizeBehavioralPattern(_In_ const SystemCallStatistics* SystemCallStats,
                                    _In_ const IRPPatternStatistics* IrpStats,
                                    _In_ const KernelList<KernelAPIPattern*>* ApiPatterns,
                                    _Out_ PatternAnalysisResult* PatternResult);

// Alert management utilities
NTSTATUS CreateBehavioralAlert(_In_ const PatternAnalysisResult* PatternResult);
NTSTATUS GetActiveBehavioralAlerts(_Out_ KernelList<PatternAnalysisResult*>* Alerts);
NTSTATUS ClearBehavioralAlerts();

} // namespace BootkitFramework