"""Scanner engine tests."""

from app.services.scanner import TLSScanner


def test_parse_cipher_suite_ecdhe():
    scanner = TLSScanner()
    result = scanner._parse_cipher_suite("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
    assert result["key_exchange"] == "ECDHE"
    assert result["authentication"] == "RSA"
    assert result["encryption"] == "AES-256-GCM"
    assert result["mac"] == "SHA384"
    assert result["is_quantum_safe"] is False


def test_parse_cipher_suite_pqc():
    scanner = TLSScanner()
    result = scanner._parse_cipher_suite("TLS_MLKEM768_WITH_AES_256_GCM_SHA384")
    assert result["is_quantum_safe"] is True
    assert result["pqc_algorithm"] == "ML-KEM"


def test_parse_cipher_suite_deprecated():
    scanner = TLSScanner()
    result = scanner._parse_cipher_suite("TLS_RSA_WITH_RC4_128_SHA")
    assert result["is_deprecated"] is True


def test_quantum_assessment_not_safe():
    scanner = TLSScanner()
    scan_data = {
        "tls_info": {"version": "TLSv1.2"},
        "certificate": {
            "is_quantum_safe": False,
            "is_expired": False,
            "is_self_signed": False,
            "public_key_algorithm": "RSA",
            "public_key_size": 2048,
            "signature_algorithm": "sha256WithRSAEncryption",
        },
        "ciphers": [
            {"cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "is_quantum_safe": False, "is_deprecated": False, "protocol_version": "TLSv1.2"},
        ],
        "key_exchange": {"algorithm": "ECDHE", "is_quantum_safe": False},
    }
    assessment = scanner._assess_quantum_safety(scan_data)
    assert assessment["overall_quantum_safe"] is False
    assert assessment["label_type"] in ("not_quantum_safe", "partial")
    assert len(assessment["recommendations"]) > 0


def test_quantum_assessment_safe():
    scanner = TLSScanner()
    scan_data = {
        "tls_info": {"version": "TLSv1.3"},
        "certificate": {
            "is_quantum_safe": True,
            "is_expired": False,
            "is_self_signed": False,
            "public_key_algorithm": "ML-DSA",
            "public_key_size": 2048,
            "signature_algorithm": "ML-DSA-65",
        },
        "ciphers": [
            {"cipher_suite": "TLS_MLKEM768_AES_256_GCM_SHA384", "is_quantum_safe": True, "is_deprecated": False, "pqc_algorithm": "ML-KEM", "protocol_version": "TLSv1.3"},
        ],
        "key_exchange": {"algorithm": "ML-KEM-768", "is_quantum_safe": True},
    }
    assessment = scanner._assess_quantum_safety(scan_data)
    assert assessment["overall_quantum_safe"] is True
    assert assessment["nist_compliance"]["ml_kem"] is True


def test_vulnerability_detection_hndl():
    scanner = TLSScanner()
    scan_data = {
        "tls_info": {"version": "TLSv1.2"},
        "certificate": {"is_quantum_safe": False, "is_expired": False, "public_key_algorithm": "RSA", "signature_algorithm": "sha256WithRSAEncryption"},
        "ciphers": [],
        "key_exchange": {"algorithm": "RSA", "is_quantum_safe": False},
    }
    vulns = scanner._assess_vulnerabilities(scan_data)
    hndl_vulns = [v for v in vulns if v["category"] == "hndl_risk"]
    assert len(hndl_vulns) > 0


def test_cbom_generation():
    scanner = TLSScanner()
    scan_data = {
        "tls_info": {"version": "TLSv1.3"},
        "certificate": {
            "public_key_algorithm": "RSA",
            "public_key_size": 2048,
            "signature_algorithm": "sha256WithRSAEncryption",
            "is_quantum_safe": False,
        },
        "ciphers": [
            {"cipher_suite": "TLS_AES_256_GCM_SHA384", "is_quantum_safe": False, "is_deprecated": False, "protocol_version": "TLSv1.3", "encryption": "AES-256-GCM", "key_size": 256},
        ],
        "key_exchange": {"algorithm": "ECDHE", "is_quantum_safe": False},
    }
    entries = scanner._generate_cbom_entries(scan_data)
    assert len(entries) >= 3  # TLS, cert, key_exchange at minimum
    assert any(e["component_type"] == "tls_certificate" for e in entries)
    assert any(e["component_type"] == "key_exchange" for e in entries)


def test_pqc_recommendations():
    scanner = TLSScanner()
    assert "ML-KEM" in scanner.PQC_RECOMMENDATIONS["ECDHE"]
    assert "ML-DSA" in scanner.PQC_RECOMMENDATIONS["RSA"]
