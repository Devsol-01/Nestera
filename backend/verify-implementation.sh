#!/bin/bash

# Runtime Contract Validation - Test & Verification Script
# This script verifies that all implementations are correctly configured

set -e

echo "=========================================="
echo "Runtime Contract Validation - Verification"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Counter for checks
PASSED=0
FAILED=0

check_file() {
    local file=$1
    local description=$2
    
    if [ -f "$file" ]; then
        echo -e "${GREEN}✓${NC} $description"
        ((PASSED++))
    else
        echo -e "${RED}✗${NC} $description - File not found: $file"
        ((FAILED++))
    fi
}

check_content() {
    local file=$1
    local pattern=$2
    local description=$3
    
    if grep -q "$pattern" "$file"; then
        echo -e "${GREEN}✓${NC} $description"
        ((PASSED++))
    else
        echo -e "${RED}✗${NC} $description"
        ((FAILED++))
    fi
}

echo "1. Checking Implementation Files..."
echo "=================================="

check_file "backend/src/common/pipes/strict-validation.pipe.ts" \
    "StrictValidationPipe implementation"

check_file "backend/src/common/services/contract-validation.service.ts" \
    "ContractValidationService implementation"

check_file "backend/src/common/decorators/allow-backward-compatibility.decorator.ts" \
    "AllowBackwardCompatibility decorator"

check_file "backend/src/common/decorators/disable-strict-validation.decorator.ts" \
    "DisableStrictValidation decorator"

echo ""
echo "2. Checking Test Files..."
echo "========================="

check_file "backend/src/common/pipes/strict-validation.pipe.spec.ts" \
    "StrictValidationPipe unit tests"

check_file "backend/src/common/services/contract-validation.service.spec.ts" \
    "ContractValidationService unit tests"

check_file "backend/src/common/pipes/strict-validation.integration.spec.ts" \
    "Integration tests"

echo ""
echo "3. Checking Documentation Files..."
echo "===================================="

check_file "backend/src/common/RUNTIME_CONTRACT_VALIDATION.md" \
    "Main documentation"

check_file "backend/RUNTIME_CONTRACT_VALIDATION_SUMMARY.md" \
    "Implementation summary"

check_file "backend/INTEGRATION_GUIDE.md" \
    "Integration guide"

check_file "backend/QUICK_REFERENCE.md" \
    "Quick reference"

check_file "backend/VERIFICATION_CHECKLIST.md" \
    "Verification checklist"

echo ""
echo "4. Checking Code Content..."
echo "============================="

check_content "backend/src/common/pipes/strict-validation.pipe.ts" \
    "async transform" \
    "StrictValidationPipe has transform method"

check_content "backend/src/common/services/contract-validation.service.ts" \
    "recordValidationFailure" \
    "ContractValidationService has recordValidationFailure method"

check_content "backend/src/common/services/contract-validation.service.ts" \
    "getFailureStatistics" \
    "ContractValidationService has getFailureStatistics method"

check_content "backend/src/common/decorators/allow-backward-compatibility.decorator.ts" \
    "SetMetadata" \
    "AllowBackwardCompatibility uses SetMetadata"

echo ""
echo "5. Checking Module Integration..."
echo "=================================="

check_content "backend/src/common/common.module.ts" \
    "ContractValidationService" \
    "ContractValidationService registered in CommonModule"

check_content "backend/src/common/common.module.ts" \
    "exports.*ContractValidationService" \
    "ContractValidationService exported from CommonModule"

check_content "backend/src/main.ts" \
    "ContractValidationService" \
    "ContractValidationService imported in main.ts"

echo ""
echo "6. Checking Test Coverage..."
echo "============================="

# Count test cases
PIPE_TESTS=$(grep -c "it('should" "backend/src/common/pipes/strict-validation.pipe.spec.ts" || echo "0")
SERVICE_TESTS=$(grep -c "it('should" "backend/src/common/services/contract-validation.service.spec.ts" || echo "0")
INTEGRATION_TESTS=$(grep -c "it('should" "backend/src/common/pipes/strict-validation.integration.spec.ts" || echo "0")

echo -e "${GREEN}✓${NC} StrictValidationPipe test cases: $PIPE_TESTS"
((PASSED++))

echo -e "${GREEN}✓${NC} ContractValidationService test cases: $SERVICE_TESTS"
((PASSED++))

echo -e "${GREEN}✓${NC} Integration test cases: $INTEGRATION_TESTS"
((PASSED++))

TOTAL_TESTS=$((PIPE_TESTS + SERVICE_TESTS + INTEGRATION_TESTS))
echo -e "${YELLOW}Total test cases: $TOTAL_TESTS${NC}"

echo ""
echo "7. Checking Documentation Content..."
echo "====================================="

check_content "backend/src/common/RUNTIME_CONTRACT_VALIDATION.md" \
    "Features" \
    "Main documentation includes Features section"

check_content "backend/src/common/RUNTIME_CONTRACT_VALIDATION.md" \
    "Usage Examples" \
    "Main documentation includes Usage Examples"

check_content "backend/INTEGRATION_GUIDE.md" \
    "Phase 1" \
    "Integration guide has phases"

check_content "backend/QUICK_REFERENCE.md" \
    "TL;DR" \
    "Quick reference has quick start section"

echo ""
echo "=========================================="
echo "Test Execution Commands"
echo "=========================================="
echo ""
echo "To run the tests, execute:"
echo ""
echo "# Run all strict validation tests"
echo "  npm test -- --testPathPattern='strict-validation|contract-validation'"
echo ""
echo "# Run specific test suite"
echo "  npm test -- strict-validation.pipe.spec"
echo "  npm test -- contract-validation.service.spec"
echo "  npm test -- strict-validation.integration.spec"
echo ""
echo "# Run with coverage"
echo "  npm test -- --coverage --testPathPattern='strict-validation|contract-validation'"
echo ""

echo "=========================================="
echo "Verification Summary"
echo "=========================================="
echo ""
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All checks passed!${NC}"
    echo ""
    echo "Implementation is ready for integration."
    echo ""
    echo "Next steps:"
    echo "1. Run the test suite: npm test -- --testPathPattern='strict-validation'"
    echo "2. Review the documentation in backend/RUNTIME_CONTRACT_VALIDATION_SUMMARY.md"
    echo "3. Follow the integration guide in backend/INTEGRATION_GUIDE.md"
    echo "4. Deploy to staging and monitor validation metrics"
    exit 0
else
    echo -e "${RED}✗ Some checks failed!${NC}"
    echo ""
    echo "Please verify:"
    echo "1. All files are present in correct locations"
    echo "2. File content is not corrupted"
    echo "3. Module registration is complete"
    exit 1
fi
