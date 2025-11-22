from flask import Flask, render_template, request, jsonify, make_response
import base64
import hashlib
import hmac

app = Flask(__name__)

# The correct password hash that players need to crack (SHA1 of "hamburguesa")
CORRECT_PASSWORD_HASH = "9a1e795ae0c1d04fe935a9a39d88276ddfd3e2e3"

def encode_admin_header(value):
    """Encode admin=value with 5x base64 + hex"""
    text = f"admin={value}"
    # Encode 5 times with base64
    for _ in range(5):
        text = base64.b64encode(text.encode()).decode()
    # Final hex encoding (ASCII to hex)
    return text.encode().hex()

def decode_admin_header(encoded):
    """Decode hex + 5x base64"""
    try:
        # Decode hex first
        text = bytes.fromhex(encoded).decode()
        # Decode base64 5 times
        for _ in range(5):
            text = base64.b64decode(text).decode()
        return text
    except:
        return None

@app.route('/')
def index():
    return render_template('index.html')

# Directory fuzzing routes - return 401 for valid paths in the chain
@app.route('/atom')
@app.route('/atom/')
@app.route('/atom/<path:subpath>')
def atom_paths(subpath=''):
    # Valid paths in the chain should return 401
    valid_paths = [
        '',  # /atom
        'operations',
        'operations/oracle',
        'operations/oracle/proxy'
    ]
    
    if subpath in valid_paths:
        return 'Unauthorized', 401
    
    return 'Not Found', 404

@app.route('/atom/operations/oracle/proxy/admin', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def admin_endpoint():
    # Check for custom header with encoded admin=true
    auth_header = request.headers.get('X-Admin-Auth', '')
    
    decoded = decode_admin_header(auth_header)
    
    if decoded == 'admin=true':
        return render_template('admin_dashboard.html')
    
    # Return 401 with encoded admin=false header
    response = make_response('Unauthorized', 401)
    response.headers['X-Admin-Auth'] = encode_admin_header('false')
    return response

@app.route('/atom/operations/oracle/proxy/admin/console', methods=['GET', 'POST'])
def console():
    if request.method == 'POST':
        password = request.json.get('password', '')
        
        # Player needs to crack the SHA1 hash from chat using rockyou.txt
        # Simply compute SHA1 of their password attempt
        computed_hash = hashlib.sha1(password.encode()).hexdigest()
        
        if computed_hash == CORRECT_PASSWORD_HASH:
            return jsonify({
                'success': True,
                'message': 'Access Granted',
                'logs': [
                    {'timestamp': '2024-11-15 09:23:11', 'level': 'INFO', 'message': 'Database backup completed successfully'},
                    {'timestamp': '2024-11-15 10:45:33', 'level': 'INFO', 'message': 'All resources migrated to coreline.nu/temp'},
                    {'timestamp': '2024-11-15 10:47:12', 'level': 'INFO', 'message': 'In accordance with the CTO all resources has been moved, I have already removed everything and found a subdomain to place it with a robots that will disallow the location. I have also removed the /temp endpoint so it\'s all good'},
                    {'timestamp': '2024-11-15 11:02:45', 'level': 'INFO', 'message': 'Cleanup completed - migration endpoint removed'},
                    {'timestamp': '2024-11-15 11:15:22', 'level': 'INFO', 'message': 'System ready for production'},
                ]
            })
        else:
            return jsonify({'success': False, 'message': 'Invalid password'}), 401
    
    return render_template('console.html')

# Catch-all for other routes
@app.errorhandler(404)
def not_found(e):
    return 'Not Found', 404

if __name__ == '__main__':
    # Print the encoded header for testing
    print("Encoded admin=false:", encode_admin_header('false'))
    print("Encoded admin=true:", encode_admin_header('true'))
    print("Target password hash (SHA1):", CORRECT_PASSWORD_HASH)
    
    app.run(host='0.0.0.0', port=5000, debug=False)
