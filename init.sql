CREATE TABLE IF NOT EXISTS vulnerability_logs (
    id SERIAL PRIMARY KEY,
    scan_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    target_artifact VARCHAR(255) NOT NULL,
    cve_id VARCHAR(100) NOT NULL,
    package_name VARCHAR(255) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    ai_suggested_patch TEXT,
    human_action VARCHAR(50) NOT NULL
);
