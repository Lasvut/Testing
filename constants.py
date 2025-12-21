"""
WAF System Constants

OPTIMIZATION: Centralized configuration constants to eliminate magic numbers
and improve code readability and maintainability.

All time values are in seconds unless otherwise noted.
"""

# ==========================================
# TIME WINDOWS (seconds)
# ==========================================
WINDOW_10_SECONDS = 10
WINDOW_1_MINUTE = 60
WINDOW_5_MINUTES = 300
WINDOW_10_MINUTES = 600
WINDOW_1_HOUR = 3600

# ==========================================
# RATE LIMITING
# ==========================================
DEFAULT_PER_IP_LIMIT = 100          # Requests per minute per IP
DEFAULT_GLOBAL_LIMIT = 1000         # Requests per minute globally
DEFAULT_BURST_LIMIT = 20            # Burst requests per 10 seconds
DEFAULT_LOGIN_LIMIT = 30            # Login attempts per minute

# ==========================================
# DEQUE/WINDOW SIZES
# ==========================================
MAX_IP_WINDOW_SIZE = 1000           # Per-IP request tracking
MAX_GLOBAL_WINDOW_SIZE = 5000       # Global attack tracking
MAX_IP_PATH_WINDOW_SIZE = 1000      # Per-IP-path tracking
MAX_ATTACK_TYPE_WINDOW_SIZE = 1000  # Per attack type tracking
MAX_GLOBAL_ATTACK_WINDOW_SIZE = 5000 # Global attack window

# Rate limiter specific
RATE_LIMITER_IP_WINDOW = 10000
RATE_LIMITER_GLOBAL_WINDOW = 100000
RATE_LIMITER_PATH_WINDOW = 1000

# ==========================================
# CLEANUP INTERVALS
# ==========================================
CLEANUP_INTERVAL = 300              # 5 minutes between cleanups
CLEANUP_CUTOFF_TIME = 300           # Remove entries older than 5 minutes
BASELINE_UPDATE_INTERVAL = 300      # Update baseline rates every 5 minutes

# ==========================================
# MACHINE LEARNING
# ==========================================
SVM_DEFAULT_THRESHOLD = 0.5         # Probability threshold (0.0-1.0)
SVM_REGULARIZATION_C = 0.5          # SVM regularization parameter
MAX_TFIDF_FEATURES = 10000          # Maximum TF-IDF features
NGRAM_SIZE = 3                      # Character n-gram size (trigrams)
SVM_MAX_ITERATIONS = 3000           # Training iterations

# Anomaly detection thresholds
ANOMALY_SCORE_THRESHOLD = 100       # Base anomaly score threshold
MIN_TRAINING_NORMAL_SAMPLES = 100   # Minimum normal samples for training
MIN_TRAINING_ATTACK_SAMPLES = 50    # Minimum attack samples for training

# Dataset limits
MAX_NORMAL_SAMPLES = 7000           # Maximum normal samples to load
MAX_ATTACK_SAMPLES = 4500           # Maximum attack samples to load
MIN_CSV_SAMPLES = 50                # Minimum samples before using CSV data

# ==========================================
# FLOOD DETECTION
# ==========================================
FLOOD_THRESHOLD_PER_IP = 10         # Attacks per minute to trigger flood alert
FLOOD_THRESHOLD_TOTAL = 50          # Total attacks per minute for distributed flood
FLOOD_VELOCITY_MULTIPLIER = 3.0     # Multiplier for velocity spike detection
FLOOD_TYPE_CONCENTRATION_PCT = 80   # Percentage for attack type concentration
FLOOD_MIN_ATTACKS_FOR_CONCENTRATION = 20  # Minimum attacks for type concentration

# ==========================================
# ALERT COOLDOWNS (seconds)
# ==========================================
ALERT_COOLDOWN_FLOOD = 300          # 5 minutes between flood alerts
ALERT_COOLDOWN_CRITICAL = 60        # 1 minute between critical alerts
ALERT_COOLDOWN_CONFIG = 300         # 5 minutes between config alerts
ALERT_COOLDOWN_SYSTEM = 300         # 5 minutes between system alerts

# ==========================================
# DATABASE
# ==========================================
DB_NAME = "app_data.db"

# ==========================================
# HTTP/RESPONSE
# ==========================================
HTTP_STATUS_FORBIDDEN = 403
HTTP_STATUS_TOO_MANY_REQUESTS = 429
HTTP_STATUS_UNAUTHORIZED = 401

# ==========================================
# PAYLOAD LIMITS
# ==========================================
MAX_PAYLOAD_LOG_LENGTH = 500        # Maximum payload length to log
MAX_PATTERN_DISPLAY_LENGTH = 50     # Maximum pattern length to display
MAX_RECENT_LOGS_DEFAULT = 50        # Default number of recent logs
MAX_RECENT_LOGS_MONITOR = 200       # Logs shown in monitor view

# ==========================================
# FILE PATHS
# ==========================================
SVM_MODEL_PATH = 'improved_svm_model.pkl'
ANOMALY_MODEL_PATH = 'anomaly_detector_model.pkl'
CSIC_DATASET_PATH = 'datasets/csic2010/CSIC_2010.csv'
WAF_CONFIG_FILE = 'waf_config.json'
ALERT_CONFIG_FILE = 'alert_config.json'

# ==========================================
# NETWORK
# ==========================================
DEFAULT_IP_FALLBACK = '0.0.0.0'
LOCALHOST_IP = '127.0.0.1'

# ==========================================
# ATTACK GENERATOR
# ==========================================
ATTACK_GENERATOR_DEFAULT_INTERVAL = 30  # Seconds between attack batches
ATTACK_GENERATOR_DEFAULT_COUNT = 75     # Number of attacks per batch

# ==========================================
# ALERT SYSTEM
# ==========================================
# Alert severity emoji mappings
ALERT_SEVERITY_EMOJI = {
    'CRITICAL': '🚨',
    'WARNING': '⚠️',
    'INFO': 'ℹ️'
}

# Alert type name mappings
ALERT_TYPE_NAMES = {
    'flood': 'Attack Flood',
    'critical_attack': 'Critical Attack',
    'config_change': 'Configuration Change',
    'system_health': 'System Health Alert'
}

# Discord color mappings (decimal values)
ALERT_SEVERITY_COLORS_DISCORD = {
    'CRITICAL': 15158332,  # Red
    'WARNING': 16776960,   # Yellow
    'INFO': 3447003        # Blue
}

# HTML/Email color mappings (hex values)
ALERT_SEVERITY_COLORS_HTML = {
    'CRITICAL': '#dc3545',  # Red
    'WARNING': '#ffc107',   # Yellow
    'INFO': '#17a2b8'       # Blue
}
