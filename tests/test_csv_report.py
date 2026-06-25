from dnx.output.csv_report import write_csv_report


def sample_result():
    return {
        "target": {"domain": "example.com"},
        "records": {"A": {"values": ["93.184.216.34"], "error": None, "nameserver": "1.1.1.1"}},
        "nameservers": {"servers": []},
        "subdomains": {"unique_subdomains": [], "source_map": {}, "verified_subdomains": []},
        "findings": [],
    }


def test_csv_report_written(tmp_path):
    path = write_csv_report(sample_result(), tmp_path)
    data = path.read_text(encoding="utf-8")
    assert "category,name,value" in data
    assert "dns_record,A,93.184.216.34" in data
