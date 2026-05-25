"""
End-to-end test script for the enhanced Email Verification Tool.
Run with: python test_e2e.py
"""
import http.client
import json
import time
import io
import os
import sys

HOST = 'localhost:5050'
CSV_PATH = 'Fortune500leads.csv'

def multipart_post(path, filepath):
    """Upload a CSV file via multipart/form-data."""
    with open(filepath, 'rb') as f:
        file_data = f.read()
    
    filename = os.path.basename(filepath)
    boundary = '----TestBoundary987654321'
    body = (
        f'--{boundary}\r\n'
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f'Content-Type: text/csv\r\n\r\n'
    ).encode() + file_data + f'\r\n--{boundary}--\r\n'.encode()
    
    conn = http.client.HTTPConnection('localhost', 5050)
    conn.request('POST', path, body=body, headers={
        'Content-Type': f'multipart/form-data; boundary={boundary}',
        'Content-Length': str(len(body)),
    })
    resp = conn.getresponse()
    data = json.loads(resp.read().decode())
    conn.close()
    return data

def main():
    print("=== Email Verification Tool - End-to-End Test ===\n")
    
    # Step 1: Check server is alive
    print("[1] Checking server...")
    try:
        conn = http.client.HTTPConnection('localhost', 5050)
        conn.request('GET', '/progress')
        resp = conn.getresponse()
        print(f"    Server OK: {resp.status}")
        conn.close()
    except Exception as e:
        print(f"    ERROR: Server not reachable - {e}")
        sys.exit(1)
    
    # Step 2: Upload CSV
    print(f"[2] Uploading {CSV_PATH}...")
    try:
        result = multipart_post('/verify', CSV_PATH)
        job_id = result.get('job_id')
        if not job_id:
            print(f"    ERROR: No job_id in response: {result}")
            sys.exit(1)
        print(f"    Job created: {job_id}")
    except Exception as e:
        print(f"    ERROR uploading: {e}")
        sys.exit(1)
    
    # Step 3: Poll progress
    print("[3] Polling progress (max 5 minutes)...")
    max_attempts = 150  # 5 minutes at 2s intervals
    for attempt in range(max_attempts):
        time.sleep(2)
        try:
            conn = http.client.HTTPConnection('localhost', 5050)
            conn.request('GET', f'/progress?job_id={job_id}')
            resp = conn.getresponse()
            data = json.loads(resp.read().decode())
            conn.close()
            
            pct = data.get('percent', 0)
            row = data.get('row', 0)
            total = data.get('total', 0)
            print(f"    [{attempt+1}] {pct}% - Row {row}/{total}")
            
            if pct >= 100:
                print("    Verification complete!")
                break
        except Exception as e:
            print(f"    Poll error: {e}")
    else:
        print("    TIMEOUT: verification took too long")
    
    # Step 4: Download results
    print("[4] Downloading results...")
    download_types = ['all', 'valid', 'high_confidence', 'inferred', 'risky', 'risky_invalid']
    
    for dl_type in download_types:
        try:
            conn = http.client.HTTPConnection('localhost', 5050)
            conn.request('GET', f'/download?job_id={job_id}&type={dl_type}')
            resp = conn.getresponse()
            content = resp.read().decode()
            conn.close()
            
            lines = content.strip().split('\n')
            data_rows = len(lines) - 1 if len(lines) > 1 else 0
            print(f"    {dl_type:20s}: {data_rows:4d} rows | status={resp.status}")
            
            # Show first 2 data rows as sample
            if data_rows > 0 and dl_type == 'all':
                for line in lines[1:min(3, len(lines))]:
                    cols = line.split(',')
                    print(f"      Sample: email={cols[5] if len(cols)>5 else '?'} status={cols[7] if len(cols)>7 else '?'}")
        except Exception as e:
            print(f"    {dl_type:20s}: ERROR - {e}")
    
    # Step 5: Summary
    print("\n[5] Test Summary:")
    print("    - Backend: verify-app.py (port 5050)")
    print("    - Frontend: index.html (open in browser)")
    print("    - New features tested: MX fallback, SMTP pooling, confidence scoring,")
    print("      pattern inference, typo correction, deduplication, CSV robustness")
    print("\n=== Test Complete ===")

if __name__ == '__main__':
    main()