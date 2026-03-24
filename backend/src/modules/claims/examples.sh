#!/bin/bash

# Medical Claims API - Usage Examples
# Make sure the backend is running: pnpm start:dev

BASE_URL="http://localhost:3001/api"

echo "=========================================="
echo "Medical Claims Submission API - Examples"
echo "=========================================="
echo ""

# Example 1: Submit a valid claim
echo "1. Submitting a valid medical claim..."
curl -X POST "${BASE_URL}/claims" \
  -H "Content-Type: application/json" \
  -d '{
    "patientName": "Jane Smith",
    "patientId": "PAT-456789",
    "patientDateOfBirth": "1985-05-20",
    "hospitalName": "General Hospital",
    "hospitalId": "HOSP-GH2024",
    "diagnosisCodes": ["J18.9", "A09"],
    "claimAmount": 2500.75,
    "notes": "Emergency treatment for pneumonia"
  }' | jq '.'

echo ""
echo "=========================================="
echo ""

# Example 2: Submit claim without optional notes
echo "2. Submitting claim without notes..."
curl -X POST "${BASE_URL}/claims" \
  -H "Content-Type: application/json" \
  -d '{
    "patientName": "John Doe",
    "patientId": "PAT-123456",
    "patientDateOfBirth": "1990-01-15",
    "hospitalName": "City General Hospital",
    "hospitalId": "HOSP-ABC123",
    "diagnosisCodes": ["A09"],
    "claimAmount": 5000.50
  }' | jq '.'

echo ""
echo "=========================================="
echo ""

# Example 3: Invalid diagnosis code (should fail)
echo "3. Testing invalid diagnosis code (should fail)..."
curl -X POST "${BASE_URL}/claims" \
  -H "Content-Type: application/json" \
  -d '{
    "patientName": "Test Patient",
    "patientId": "PAT-999",
    "patientDateOfBirth": "1995-03-10",
    "hospitalName": "Test Hospital",
    "hospitalId": "HOSP-TEST01",
    "diagnosisCodes": ["INVALID"],
    "claimAmount": 1000
  }' | jq '.'

echo ""
echo "=========================================="
echo ""

# Example 4: Invalid hospital ID format (should fail)
echo "4. Testing invalid hospital ID (should fail)..."
curl -X POST "${BASE_URL}/claims" \
  -H "Content-Type: application/json" \
  -d '{
    "patientName": "Test Patient",
    "patientId": "PAT-999",
    "patientDateOfBirth": "1995-03-10",
    "hospitalName": "Test Hospital",
    "hospitalId": "INVALID-FORMAT",
    "diagnosisCodes": ["A09"],
    "claimAmount": 1000
  }' | jq '.'

echo ""
echo "=========================================="
echo ""

# Example 5: Negative amount (should fail)
echo "5. Testing negative claim amount (should fail)..."
curl -X POST "${BASE_URL}/claims" \
  -H "Content-Type: application/json" \
  -d '{
    "patientName": "Test Patient",
    "patientId": "PAT-999",
    "patientDateOfBirth": "1995-03-10",
    "hospitalName": "Test Hospital",
    "hospitalId": "HOSP-TEST01",
    "diagnosisCodes": ["A09"],
    "claimAmount": -500
  }' | jq '.'

echo ""
echo "=========================================="
echo ""

# Example 6: Get all claims
echo "6. Retrieving all claims..."
curl -X GET "${BASE_URL}/claims" \
  -H "Content-Type: application/json" | jq '.'

echo ""
echo "=========================================="
echo ""

# Example 7: Multiple diagnosis codes
echo "7. Submitting claim with multiple diagnosis codes..."
curl -X POST "${BASE_URL}/claims" \
  -H "Content-Type: application/json" \
  -d '{
    "patientName": "Alice Johnson",
    "patientId": "PAT-789012",
    "patientDateOfBirth": "1978-11-30",
    "hospitalName": "Metropolitan Medical Center",
    "hospitalId": "HOSP-MMC001",
    "diagnosisCodes": ["E11.9", "I10", "J44.0"],
    "claimAmount": 15000.00,
    "notes": "Diabetes management, hypertension, and COPD treatment"
  }' | jq '.'

echo ""
echo "=========================================="
echo "Examples completed!"
echo "=========================================="
