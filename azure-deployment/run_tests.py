#!/usr/bin/env python3
"""
Test runner script for WebAuthn Investor Verification System - Phase 5

Runs comprehensive test suite with reporting and coverage.
"""

import subprocess
import sys
import os

def run_command(command, description=""):
    """Run a command and handle errors."""
    print(f"\n{'='*60}")
    print(f"🧪 {description}")
    print(f"{'='*60}")
    
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Command failed: {e}")
        print(f"STDOUT: {e.stdout}")
        print(f"STDERR: {e.stderr}")
        return False

def main():
    """Main test runner."""
    print("🚀 WebAuthn Investor Verification System - Test Suite")
    print("Phase 5: Clean Architecture Testing")
    
    # Change to project directory
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    test_commands = [
        {
            "command": "python -m pytest tests/unit/services/ -v --tb=short",
            "description": "Running Unit Tests for Services"
        },
        {
            "command": "python -m pytest tests/integration/ -v --tb=short", 
            "description": "Running Integration Tests"
        },
        {
            "command": "python -m pytest tests/ -v --tb=short -m 'not slow'",
            "description": "Running All Fast Tests"
        },
        {
            "command": "python -m pytest tests/unit/services/test_session_service.py -v",
            "description": "Running Session Service Tests"
        },
        {
            "command": "python -m pytest tests/unit/services/test_auth_service.py -v",
            "description": "Running Auth Service Tests"
        },
        {
            "command": "python -m pytest tests/unit/services/test_template_service.py -v",
            "description": "Running Template Service Tests"
        }
    ]
    
    print(f"\n📊 Test Plan: {len(test_commands)} test suites")
    
    passed = 0
    failed = 0
    
    for i, test in enumerate(test_commands, 1):
        print(f"\n[{i}/{len(test_commands)}] {test['description']}")
        
        if run_command(test["command"], test["description"]):
            print(f"✅ {test['description']} - PASSED")
            passed += 1
        else:
            print(f"❌ {test['description']} - FAILED")
            failed += 1
    
    print(f"\n{'='*60}")
    print(f"📈 TEST SUMMARY")
    print(f"{'='*60}")
    print(f"✅ Passed: {passed}")
    print(f"❌ Failed: {failed}")
    print(f"📊 Total:  {passed + failed}")
    
    if failed == 0:
        print(f"\n🎉 ALL TESTS PASSED! Clean Architecture Phase 5 Complete!")
        print(f"🏗️  Services tested: SessionService, AuthService, TemplateService")
        print(f"🔒 Security: Input validation, authentication, rate limiting")
        print(f"🌐 Hebrew RTL: Template rendering and error handling")
        print(f"⚡ Performance: JWT token management and session lifecycle")
        return 0
    else:
        print(f"\n⚠️  {failed} test suite(s) failed. Please review and fix issues.")
        return 1

if __name__ == "__main__":
    sys.exit(main())