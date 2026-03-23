-- setup.sql
-- Run this file ONCE to create the database and table
-- In MySQL Workbench: File → Open SQL Script → select this file → click Run (lightning bolt)

-- Step 1: Create the database
CREATE DATABASE IF NOT EXISTS browseguard;

-- Step 2: Switch to using it
USE browseguard;

-- Step 3: Create the visits table
CREATE TABLE IF NOT EXISTS visits (
    id          INT AUTO_INCREMENT PRIMARY KEY,   -- unique row ID, auto-fills
    url         TEXT NOT NULL,                    -- the website URL that was checked
    score       INT NOT NULL DEFAULT 100,         -- risk score (0–100)
    reasons     TEXT,                             -- why it was flagged (pipe-separated)
    flagged     TINYINT(1) NOT NULL DEFAULT 0,    -- 1 = flagged, 0 = safe
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP  -- when it was checked, auto-fills
);

-- Verify it worked — run this to see the empty table
SELECT * FROM visits;