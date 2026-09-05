from scanner.runner import ScanResults, ScanStatus, run_scan
from scanner.fixtures import FIXTURE, CLEAN_ENVIRONMENT_FIXTURE

def test_runner_fixture():
    result = run_scan(FIXTURE)

    assert result.status == ScanStatus.INCOMPLETE

    assert len(result.results) == 2

def test_clean_env_fixture_runner():
    result = run_scan(CLEAN_ENVIRONMENT_FIXTURE)

    assert result.status == ScanStatus.COMPLETED
    
    assert len(result.results) == 2


    