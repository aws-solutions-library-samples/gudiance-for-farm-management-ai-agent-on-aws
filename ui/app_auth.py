#!/usr/bin/env python3
"""
Plant Analysis UI - Flask Application with Cognito Authentication
"""

import os
import sys
import json
import base64
import uuid
import time
import logging
import boto3
import requests
import hashlib
import secrets
import re
from urllib.parse import urlencode, parse_qs, urlparse
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for, send_from_directory, session
from werkzeug.utils import secure_filename
from PIL import Image
from functools import wraps
import io
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Load environment variables
def load_env_first():
    """Load .env file before any AWS operations"""
    env_file = '.env'
    if os.path.exists(env_file):
        with open(env_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key] = value
        print("✅ Loaded .env file first")
    else:
        print("⚠️ No .env file found")

load_env_first()

try:
    from dotenv import load_dotenv
    load_dotenv()
    print("✅ python-dotenv also loaded")
except ImportError:
    print("ℹ️ python-dotenv not available")

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Suppress Flask/Werkzeug HTTP request logs
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
logging.getLogger('flask').setLevel(logging.ERROR)

app = Flask(__name__, template_folder='templates')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['PREFERRED_URL_SCHEME'] = 'https'  # Force HTTPS for URL generation
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))

# Secure session configuration
app.config.update(
    SESSION_COOKIE_SECURE=True,       # HTTPS only
    SESSION_COOKIE_HTTPONLY=True,     # No JavaScript access
    SESSION_COOKIE_SAMESITE='Lax',    # CSRF protection
    PERMANENT_SESSION_LIFETIME=3600   # 1 hour timeout
)

# Configure Flask to handle HTTPS behind CloudFront
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Initialize Flask-Limiter for rate limiting
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"],
        storage_uri="memory://"
    )
    logger.info("✅ Rate limiting enabled")
except ImportError:
    logger.warning("⚠️ flask-limiter not installed - rate limiting disabled")
    limiter = None

# Cognito Configuration from environment variables
COGNITO_USER_POOL_ID = os.environ.get('COGNITO_USER_POOL_ID')
COGNITO_CLIENT_ID = os.environ.get('COGNITO_CLIENT_ID')
COGNITO_IDENTITY_POOL_ID = os.environ.get('COGNITO_IDENTITY_POOL_ID')
COGNITO_DOMAIN = os.environ.get('COGNITO_DOMAIN')
AWS_REGION = os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')

# Global configuration variables
RUNTIME_ARN = None
ACCOUNT_ID = None
MEMORY_ROLE_ARN = None
MEMORY_NAME = None
RUNTIME_CONFIGURED = False
CLOUDFRONT_SECRET = None

# Configure requests session with timeout and retries
def get_requests_session():
    """Create requests session with timeout and retry configuration"""
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=0.3,
        status_forcelist=[500, 502, 503, 504]
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('https://', adapter)
    session.mount('http://', adapter)
    
    # Add default timeout to all requests
    original_request = session.request
    def request_with_timeout(*args, **kwargs):
        kwargs.setdefault('timeout', 10)  # 10 seconds default
        return original_request(*args, **kwargs)
    session.request = request_with_timeout
    
    return session

# Global requests session
requests_session = get_requests_session()

# Security validation functions
def validate_cognito_domain(domain):
    """Validate Cognito domain format - alphanumeric and hyphens only"""
    if not domain:
        raise ValueError("Cognito domain cannot be empty")
    if not re.match(r'^[a-z0-9-]+$', domain):
        raise ValueError(f"Invalid Cognito domain format: {domain}")
    if len(domain) > 63:
        raise ValueError(f"Cognito domain too long: {domain}")
    return domain

def validate_aws_region(region):
    """Validate AWS region format against known regions"""
    if not region:
        raise ValueError("AWS region cannot be empty")
    
    valid_regions = [
        'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
        'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-north-1',
        'ap-south-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3',
        'ap-southeast-1', 'ap-southeast-2', 'ca-central-1', 'sa-east-1',
        'af-south-1', 'me-south-1', 'ap-east-1'
    ]
    
    if region not in valid_regions:
        raise ValueError(f"Invalid AWS region: {region}")
    return region

def validate_user_pool_id(pool_id):
    """Validate Cognito User Pool ID format"""
    if not pool_id:
        raise ValueError("User Pool ID cannot be empty")
    # Format: region_randomchars (e.g., us-east-1_abc123XYZ)
    if not re.match(r'^[a-z]+-[a-z]+-\d+_[A-Za-z0-9]+$', pool_id):
        raise ValueError(f"Invalid User Pool ID format: {pool_id}")
    return pool_id

# Allowed Cognito host patterns for SSRF protection
ALLOWED_COGNITO_HOST_PATTERNS = [
    '.amazoncognito.com',
    'amazoncognito.com',
    '.amazonaws.com',
    'amazonaws.com'
]

def construct_cognito_url(domain, region, path):
    """Safely construct Cognito URLs with validation"""
    # Validate inputs
    domain = validate_cognito_domain(domain)
    region = validate_aws_region(region)
    
    # Construct URL based on path type
    if '/oauth2/' in path or path.startswith('/login') or path.startswith('/logout'):
        # Auth endpoints use domain.auth.region pattern
        url = f"https://{domain}.auth.{region}.amazoncognito.com{path}"
    else:
        # IDP endpoints use cognito-idp.region pattern
        url = f"https://cognito-idp.{region}.amazonaws.com{path}"
    
    # Validate constructed URL - allow any AWS Cognito subdomain
    parsed = urlparse(url)
    hostname = parsed.hostname or ''
    
    # Check if hostname ends with any allowed pattern or matches exactly
    is_valid = any(
        hostname.endswith(pattern) or hostname == pattern.lstrip('.')
        for pattern in ALLOWED_COGNITO_HOST_PATTERNS
    )
    
    if not is_valid:
        raise ValueError(f"Invalid Cognito URL host: {hostname}")
    
    return url


def discover_runtime_arn():
    """Discover the active runtime ARN by listing available runtimes"""
    try:
        bedrock_agentcore_control = boto3.client('bedrock-agentcore-control', 
                                               region_name=AWS_REGION,
                                               endpoint_url=f"https://bedrock-agentcore-control.{AWS_REGION}.amazonaws.com")
        
        logger.info("🔍 Discovering available AgentCore runtimes...")
        
        # List all runtimes
        response = bedrock_agentcore_control.list_agent_runtimes()
        runtimes = response.get('agentRuntimeSummaries', [])
        
        if not runtimes:
            logger.warning("⚠️ No AgentCore runtimes found")
            return None
        
        # Look for plant-related runtimes (prioritize newer ones)
        plant_runtimes = []
        for runtime in runtimes:
            runtime_name = runtime.get('agentRuntimeName', '').lower()
            if any(keyword in runtime_name for keyword in ['plant', 'memory', 'fresh']):
                plant_runtimes.append(runtime)
        
        if plant_runtimes:
            # Sort by creation time (newest first) and get the most recent
            plant_runtimes.sort(key=lambda x: x.get('creationTime', ''), reverse=True)
            selected_runtime = plant_runtimes[0]
            runtime_arn = selected_runtime['agentRuntimeArn']
            runtime_name = selected_runtime['agentRuntimeName']
            
            logger.info(f"✅ Found plant runtime: {runtime_name}")
            logger.info(f"🔗 Runtime ARN: {runtime_arn}")
            return runtime_arn
        
        # If no plant-specific runtime, use the most recent one
        if runtimes:
            runtimes.sort(key=lambda x: x.get('creationTime', ''), reverse=True)
            selected_runtime = runtimes[0]
            runtime_arn = selected_runtime['agentRuntimeArn']
            runtime_name = selected_runtime['agentRuntimeName']
            
            logger.info(f"✅ Using most recent runtime: {runtime_name}")
            logger.info(f"🔗 Runtime ARN: {runtime_arn}")
            return runtime_arn
            
    except Exception as e:
        logger.error(f"❌ Failed to discover runtime ARN: {e}")
        
        # Fallback: try to read from runtime_arn.txt if it exists
        try:
            runtime_files = ['../runtime_arn.txt', './runtime_arn.txt']
            for runtime_file in runtime_files:
                if os.path.exists(runtime_file):
                    with open(runtime_file, 'r') as f:
                        fallback_arn = f.read().strip()
                    logger.info(f"✅ Using fallback runtime ARN from {runtime_file}")
                    return fallback_arn
        except Exception as fallback_error:
            logger.error(f"❌ Fallback runtime ARN read failed: {fallback_error}")
    
    return None


def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('authenticated'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_user_credentials():
    """Get temporary AWS credentials for the authenticated user"""
    try:
        if not session.get('cognito_identity_id'):
            return None
            
        cognito_identity = boto3.client('cognito-identity', region_name=AWS_REGION)
        
        # Get credentials for identity
        response = cognito_identity.get_credentials_for_identity(
            IdentityId=session['cognito_identity_id'],
            Logins={
                f'cognito-idp.{AWS_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}': session['id_token']
            }
        )
        
        return response['Credentials']
    except Exception as e:
        logger.error(f"Failed to get user credentials: {e}")
        return None

def create_user_boto3_session():
    """Create boto3 session with user's temporary credentials"""
    credentials = get_user_credentials()
    if not credentials:
        return None
        
    return boto3.Session(
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretKey'],
        aws_session_token=credentials['SessionToken'],
        region_name=AWS_REGION
    )

def get_account_id():
    """Get current AWS account ID"""
    try:
        sts = boto3.client('sts')
        return sts.get_caller_identity()['Account']
    except Exception as e:
        logger.error(f"Failed to get account ID: {e}")
        return 'unknown'

# Generate consistent session ID to match runtime pattern
ACTOR_ID = "user_123"  # Default from LangGraph state
SESSION_ID = "plant_analysis_session_00001_demo"  # Match runtime pattern
RUNTIME_CONFIGURED = False

def load_configuration():
    """Load configuration from SSM Parameter Store and Secrets Manager (hybrid approach)"""
    global RUNTIME_ARN, ACCOUNT_ID, MEMORY_ROLE_ARN, MEMORY_NAME, RUNTIME_CONFIGURED, CLOUDFRONT_SECRET
    global COGNITO_USER_POOL_ID, COGNITO_CLIENT_ID, COGNITO_IDENTITY_POOL_ID, COGNITO_DOMAIN
    
    try:
        config_source = os.environ.get('CONFIG_SOURCE', 'env')
        
        if config_source == 'hybrid':
            # Load from SSM Parameter Store and Secrets Manager
            logger.info("🔄 Loading configuration from AWS (SSM + Secrets Manager)")
            
            # Load non-sensitive config from SSM Parameter Store
            parameter_name = os.environ.get('CONFIG_PARAMETER_NAME')
            if not parameter_name:
                raise ValueError("CONFIG_PARAMETER_NAME environment variable not set")
            
            ssm = boto3.client('ssm', region_name=AWS_REGION)
            logger.info(f"📥 Loading configuration from SSM: {parameter_name}")
            
            try:
                response = ssm.get_parameter(Name=parameter_name, WithDecryption=True)
                config = json.loads(response['Parameter']['Value'])
                logger.info("✅ Non-sensitive configuration loaded from SSM Parameter Store")
            except Exception as ssm_error:
                logger.error(f"❌ Failed to load from SSM: {ssm_error}")
                raise
            
            # Load sensitive config from Secrets Manager
            secret_arn = os.environ.get('CONFIG_SECRET_ARN')
            if not secret_arn:
                raise ValueError("CONFIG_SECRET_ARN environment variable not set")
            
            secrets = boto3.client('secretsmanager', region_name=AWS_REGION)
            logger.info(f"📥 Loading sensitive configuration from Secrets Manager")
            
            try:
                response = secrets.get_secret_value(SecretId=secret_arn)
                secret_config = json.loads(response['SecretString'])
                # Merge sensitive config into main config
                config.update(secret_config)
                logger.info("✅ Sensitive configuration loaded from Secrets Manager")
            except Exception as secret_error:
                logger.error(f"❌ Failed to load from Secrets Manager: {secret_error}")
                raise
            
        else:
            # Fallback to environment variables or app_config.json for local development
            logger.info("🔄 Loading configuration from local sources (env vars or app_config.json)")
            
            config_file = 'app_config.json'
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    config = json.load(f)
                logger.info(f"✅ Loaded config from embedded file: {config_file}")
            else:
                config = {
                    'RUNTIME_ARN': os.environ.get('RUNTIME_ARN'),
                    'GATEWAY_ID': os.environ.get('GATEWAY_ID'),
                    'REGION': AWS_REGION,
                    'MEMORY_ROLE_ARN': os.environ.get('MEMORY_ROLE_ARN'),
                    'MEMORY_NAME': os.environ.get('MEMORY_NAME'),
                    'ACCOUNT_ID': os.environ.get('ACCOUNT_ID'),
                    'COGNITO_USER_POOL_ID': os.environ.get('COGNITO_USER_POOL_ID'),
                    'COGNITO_CLIENT_ID': os.environ.get('COGNITO_CLIENT_ID'),
                    'COGNITO_IDENTITY_POOL_ID': os.environ.get('COGNITO_IDENTITY_POOL_ID'),
                    'COGNITO_DOMAIN': os.environ.get('COGNITO_DOMAIN'),
                    'CLOUDFRONT_SECRET_HEADER': os.environ.get('CLOUDFRONT_SECRET_HEADER')
                }
                logger.info("✅ Loaded config from environment variables (development mode)")
        
        # Extract configuration values
        RUNTIME_ARN = config.get('RUNTIME_ARN')
        MEMORY_ROLE_ARN = config.get('MEMORY_ROLE_ARN')
        MEMORY_NAME = config.get('MEMORY_NAME')
        ACCOUNT_ID = config.get('ACCOUNT_ID')
        CLOUDFRONT_SECRET = config.get('CLOUDFRONT_SECRET_HEADER')
        
        # Update Cognito configuration with validation
        COGNITO_USER_POOL_ID = config.get('COGNITO_USER_POOL_ID') or COGNITO_USER_POOL_ID
        COGNITO_CLIENT_ID = config.get('COGNITO_CLIENT_ID') or COGNITO_CLIENT_ID
        COGNITO_IDENTITY_POOL_ID = config.get('COGNITO_IDENTITY_POOL_ID') or COGNITO_IDENTITY_POOL_ID
        COGNITO_DOMAIN = config.get('COGNITO_DOMAIN') or COGNITO_DOMAIN

        # Validate Cognito configuration for security
        try:
            if COGNITO_DOMAIN:
                COGNITO_DOMAIN = validate_cognito_domain(COGNITO_DOMAIN)
                logger.info(f"✅ Cognito domain validated: {COGNITO_DOMAIN}")
            if COGNITO_USER_POOL_ID:
                COGNITO_USER_POOL_ID = validate_user_pool_id(COGNITO_USER_POOL_ID)
                logger.info(f"✅ User Pool ID validated: {COGNITO_USER_POOL_ID}")
            # AWS_REGION already validated in construct_cognito_url calls
            logger.info("✅ All Cognito configuration validated successfully")
        except ValueError as validation_error:
            logger.error(f"❌ Configuration validation failed: {validation_error}")
            logger.error("This is a security issue - stopping configuration load")
            raise

        # Check if RUNTIME_ARN is available, try discovery if not
        if RUNTIME_ARN:
            logger.info(f"✅ Runtime ARN found in config: {RUNTIME_ARN}")
        else:
            logger.warning("⚠️ RUNTIME_ARN not in config, trying auto-discovery...")
            RUNTIME_ARN = discover_runtime_arn()
        
        if RUNTIME_ARN:
            RUNTIME_CONFIGURED = True
            logger.info("✅ Configuration loaded successfully")
            logger.info(f"🔗 Runtime ARN: {RUNTIME_ARN}")
            logger.info(f"🌍 Region: {AWS_REGION}")
            logger.info(f"🏢 Account ID: {ACCOUNT_ID}")
            logger.info(f"🔐 Cognito User Pool: {COGNITO_USER_POOL_ID}")
            logger.info(f"🔐 Config Source: {config_source}")
        else:
            logger.error("❌ Could not find runtime ARN in configuration")
            RUNTIME_CONFIGURED = False
            
    except Exception as e:
        logger.error(f"❌ Configuration error: {e}")
        logger.error("Falling back to environment variables or local config")
        RUNTIME_CONFIGURED = False

def call_agentcore_runtime(payload):
    """Call AgentCore runtime with ECS task credentials"""
    try:
        logger.info(f"🚀 Starting AgentCore runtime call")
 
        if not RUNTIME_CONFIGURED:
            logger.error(f"❌ Runtime not configured")
            return {"error": "Runtime not configured", "status": "failed"}
        
        logger.info(f"🔍 DEBUG: RUNTIME_CONFIGURED is True, proceeding...")

        # Use bedrock-agentcore client (exactly like the working code)
        bedrock_agentcore = boto3.client('bedrock-agentcore', region_name=AWS_REGION)
        logger.info("✅ Using bedrock-agentcore client")
        
        # Create session ID for memory continuity (33+ chars required)
        session_id = "plant_analysis_session_001_extended_for_agentcore_validation"
        payload_json = json.dumps(payload)
        
        logger.info(f"📍 Runtime ARN: {RUNTIME_ARN}")
        logger.info(f"🔑 Session ID: {session_id}")
        logger.info(f"📦 Payload: {payload}")
        
        # Call AgentCore runtime exactly like the working code
        response = bedrock_agentcore.invoke_agent_runtime(
            agentRuntimeArn=RUNTIME_ARN,
            runtimeSessionId=session_id,
            payload=payload_json,
            qualifier="DEFAULT"
        )
        
        logger.info("✅ Successfully called invoke_agent_runtime")


        
        # Process response correctly with .read() method
        logger.info(f"🔍 DEBUG: Response type: {type(response)}")
        logger.info(f"🔍 DEBUG: Response keys: {list(response.keys())}")
        
        response_body = response['response'].read()
        response_data = json.loads(response_body)
        
        logger.info("✅ AgentCore runtime call successful")
        logger.info(f"🔍 DEBUG: Response data: {response_data}")
        
        return response_data
            
    except Exception as e:
        logger.error(f"❌ AgentCore runtime call failed: {e}")
        logger.error(f"🔍 DEBUG: Exception type: {type(e).__name__}")
        return {"error": str(e), "status": "failed"}

def process_image(file):
    """Process uploaded image and convert to base64"""
    try:
        image_data = file.read()
        img = Image.open(io.BytesIO(image_data))
        base64_data = base64.b64encode(image_data).decode('utf-8')
        logger.info(f"📸 Image processed: {img.format}, {img.size}")
        return base64_data
    except Exception as e:
        logger.error(f"❌ Image processing failed: {e}")
        return None


# Global conversation state
conversation_state = {
    'last_analysis': None,
    'recommended_fertilizer': None,
    'chat_history': []
}

# Load configuration on startup
load_configuration()

@app.after_request
def set_security_headers(response):
    """Set security headers on all responses"""
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: blob:; "
        "connect-src 'self';"
    )
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

@app.before_request
def validate_cloudfront_header():
    """Validate requests come from CloudFront only"""
    # Skip validation for health check endpoint
    if request.path == '/health':
        return None
    
    # Skip validation if CloudFront secret is not configured (local dev)
    if not CLOUDFRONT_SECRET:
        return None
    
    # Check for custom header from CloudFront
    header_value = request.headers.get('X-CloudFront-Secret')
    
    if not header_value or header_value != CLOUDFRONT_SECRET:
        logger.warning(f"⚠️ Unauthorized access attempt from {request.remote_addr} to {request.path}")
        return jsonify({"error": "Forbidden - Direct access not allowed"}), 403
    
    return None

@app.route('/')
def index():
    """Landing page - show login if not authenticated"""
    if session.get('authenticated'):
        return redirect(url_for('plant_analyzer_chat'))
    return render_template('landing.html')

@app.route('/login')
def login():
    """Redirect to Cognito Hosted UI for login"""
    if not all([COGNITO_DOMAIN, COGNITO_CLIENT_ID]):
        return jsonify({"error": "Cognito not configured"}), 500
    
    try:
        # Generate state parameter for security
        state = secrets.token_urlsafe(32)
        session['oauth_state'] = state
        
        # Use CloudFront domain for callback URL
        cloudfront_domain = request.headers.get('Host', request.host)
        callback_url = f"https://{cloudfront_domain}/callback"
        
        # Build Cognito login URL with proper validation
        params = {
            'client_id': COGNITO_CLIENT_ID,
            'response_type': 'code',
            'scope': 'openid email profile',
            'redirect_uri': callback_url,
            'state': state
        }
        
        login_url = construct_cognito_url(COGNITO_DOMAIN, AWS_REGION, "/login") + "?" + urlencode(params)
        
        return redirect(login_url)
    except ValueError as e:
        logger.error(f"Invalid Cognito configuration: {e}")
        return jsonify({"error": "Authentication service unavailable"}), 503

@app.route('/callback')
def callback():
    """Handle Cognito callback"""
    try:
        # Verify state parameter
        if request.args.get('state') != session.get('oauth_state'):
            return jsonify({"error": "Invalid state parameter"}), 400
        
        # Get authorization code
        code = request.args.get('code')
        if not code:
            return jsonify({"error": "No authorization code received"}), 400
        
        # Exchange code for tokens        
        token_url = f"https://{COGNITO_DOMAIN}.auth.{AWS_REGION}.amazoncognito.com/oauth2/token"
        
        # Use CloudFront domain for callback URL
        cloudfront_domain = request.headers.get('Host', request.host)
        callback_url = f"https://{cloudfront_domain}/callback"
        
        token_data = {
            'grant_type': 'authorization_code',
            'client_id': COGNITO_CLIENT_ID,
            'code': code,
            'redirect_uri': callback_url
        }
        
        # Use secure requests session with timeout
        token_response = requests_session.post(token_url, data=token_data)
        token_response.raise_for_status()
        tokens = token_response.json()
        
        # Get user info from ID token with REQUIRED verification
        id_token = tokens['id_token']
        
        # Import JWT libraries
        import jwt
        from jwt import PyJWKClient
        
        # Get JWKS from Cognito with proper URL construction
        jwks_url = construct_cognito_url(
            COGNITO_DOMAIN,
            AWS_REGION,
            f"/{COGNITO_USER_POOL_ID}/.well-known/jwks.json"
        )
        jwks_client = PyJWKClient(jwks_url)
        signing_key = jwks_client.get_signing_key_from_jwt(id_token)
        
        # CRITICAL: Verify JWT signature - NO FALLBACK
        decoded_token = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256"],
            audience=COGNITO_CLIENT_ID,
            options={"verify_signature": True}
        )
        logger.info("✅ JWT signature verified successfully")
        
        # Get Cognito Identity ID
        cognito_identity = boto3.client('cognito-identity', region_name=AWS_REGION)
        identity_response = cognito_identity.get_id(
            IdentityPoolId=COGNITO_IDENTITY_POOL_ID,
            Logins={
                f'cognito-idp.{AWS_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}': id_token
            }
        )
        
        # Store user info in session
        session['authenticated'] = True
        session['user_id'] = decoded_token['sub']
        session['username'] = decoded_token.get('cognito:username', decoded_token['sub'])
        session['email'] = decoded_token.get('email', '')
        session['id_token'] = id_token
        session['access_token'] = tokens['access_token']
        session['cognito_identity_id'] = identity_response['IdentityId']
        
        logger.info(f"✅ User authenticated: {session['username']}")
        return redirect(url_for('plant_analyzer_chat'))
        
    except Exception as e:
        logger.error(f"❌ Authentication callback failed: {e}")
        return jsonify({"error": "Authentication failed"}), 500

@app.route('/logout')
def logout():
    """Logout user and redirect to Cognito logout"""
    session.clear()
    
    try:
        # Use CloudFront domain for logout callback
        cloudfront_domain = request.headers.get('Host', request.host)
        logout_callback = f"https://{cloudfront_domain}/"
        
        logout_url = construct_cognito_url(COGNITO_DOMAIN, AWS_REGION, "/logout") + "?" + urlencode({
            'client_id': COGNITO_CLIENT_ID,
            'logout_uri': logout_callback
        })
            
        return redirect(logout_url)
    except ValueError as e:
        logger.error(f"Invalid Cognito configuration during logout: {e}")
        # Still clear session and redirect to home even if URL construction fails
        return redirect(url_for('index'))

@app.route('/chat')
@require_auth
def plant_analyzer_chat():
    """Main Plant Analyzer chat interface"""
    current_time = datetime.now().strftime('%H:%M')
    return render_template('plant_analyzer.html', 
                         runtime_configured=RUNTIME_CONFIGURED,
                         runtime_arn=RUNTIME_ARN,
                         region=AWS_REGION,
                         current_time=current_time,
                         username=session.get('username', 'User'))

@app.route('/api/analyze', methods=['POST'])
@require_auth
def analyze_plant():
    """Handle plant analysis with image upload - Rate limited to 10/min"""
    if limiter:
        limiter.limit("10 per minute")(lambda: None)()
    try:
        logger.info(f"🌱 Processing plant analysis for user: {session.get('username')}")
        
        if 'image' not in request.files:
            return jsonify({"error": "No image file provided", "status": "failed"})
        
        file = request.files['image']
        if file.filename == '':
            return jsonify({"error": "No image file selected", "status": "failed"})
        
        image_data = process_image(file)
        if not image_data:
            return jsonify({"error": "Invalid image file", "status": "failed"})
        
        payload = {
            "prompt": "Analyze my plant",
            "image_data": image_data
        }
        
        # Call AgentCore runtime using ECS task role credentials
        result = call_agentcore_runtime(payload)
        
        # Store analysis in conversation state
        if result.get('status') == 'success':
            logger.info("✅ Plant analysis completed successfully")
            conversation_state['last_analysis'] = result
            conversation_state['recommended_fertilizer'] = result.get('recommended_fertilizer')
            
            # Add to chat history
            conversation_state['chat_history'].append({
                'type': 'analysis',
                'timestamp': datetime.now().isoformat(),
                'result': result
            })
            
            logger.info("✅ Plant analysis completed successfully")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"❌ Analysis failed: {e}")
        return jsonify({"error": str(e), "status": "failed"})

@app.route('/api/history', methods=['POST'])
@require_auth
def get_history():
    """Retrieve analysis history - Routes to LangGraph retrieve_memory state"""
    try:
        logger.info("📋 Processing history retrieval request...")
        logger.info(f"🔍 DEBUG: RUNTIME_CONFIGURED = {RUNTIME_CONFIGURED}")
        logger.info(f"🔍 DEBUG: RUNTIME_ARN = {RUNTIME_ARN}")
        
        # Prepare API payload for history retrieval (triggers retrieve_memory state)
        payload = {
            "prompt": "Show me my previous plant analyses"
        }
        
        logger.info(f"🔍 DEBUG: About to call AgentCore with payload: {payload}")
        
        # Call AgentCore runtime
        result = call_agentcore_runtime(payload)
        
        logger.info("🔍 DEBUG: ===== RAW AGENTCORE RESPONSE =====")
        logger.info(f"🔍 DEBUG: Full result: {json.dumps(result, indent=2)}")
        logger.info(f"🔍 DEBUG: Result type: {type(result)}")
        logger.info(f"🔍 DEBUG: Result status: {result.get('status')}")
        logger.info(f"🔍 DEBUG: Result keys: {list(result.keys()) if isinstance(result, dict) else 'Not a dict'}")
        
        if result.get('final_report'):
            logger.info(f"🔍 DEBUG: Final report length: {len(result.get('final_report', ''))}")
            logger.info(f"🔍 DEBUG: Final report preview: {result.get('final_report', '')[:300]}...")
        
        if result.get('error'):
            logger.info(f"🔍 DEBUG: Error in result: {result.get('error')}")
            
        logger.info("🔍 DEBUG: ===== END RAW AGENTCORE RESPONSE =====")
        
        # Format the history response for better readability
        if result.get('status') == 'success' and result.get('final_report'):
            final_report = result.get('final_report', '')
            
            # Check if this looks like raw history data that needs formatting
            if 'Plant Analysis History' in final_report and not final_report.startswith('# 📋'):
                # This looks like raw history data - let's format it better
                lines = final_report.split('\n')
                formatted_report = "# 📋 Your Plant Analysis History\n\n"
                
                analysis_count = 0
                for line in lines[2:]:  # Skip the header lines
                    line = line.strip()
                    if line and not line.startswith('#'):
                        analysis_count += 1
                        # Try to parse structured data
                        if 'Plant:' in line and 'Health:' in line and 'Advice:' in line:
                            # Parse structured analysis
                            parts = line.split('Health:')
                            if len(parts) >= 2:
                                plant_part = parts[0].replace('Plant:', '').strip()
                                health_advice = parts[1].split('Advice:')
                                if len(health_advice) >= 2:
                                    health_part = health_advice[0].strip()
                                    advice_part = health_advice[1].strip()
                                    
                                    formatted_report += f"## 🌱 Analysis #{analysis_count}\n"
                                    formatted_report += f"**Plant Type:** {plant_part}\n"
                                    formatted_report += f"**Health Status:** {health_part}\n"
                                    formatted_report += f"**Care Advice:** {advice_part}\n\n"
                                    formatted_report += "---\n\n"
                        else:
                            # Fallback formatting
                            formatted_report += f"## 📝 Analysis #{analysis_count}\n"
                            clean_line = line[:200] + "..." if len(line) > 200 else line
                            formatted_report += f"{clean_line}\n\n---\n\n"
                
                if analysis_count > 0:
                    formatted_report += f"Found **{analysis_count}** previous analysis{'es' if analysis_count != 1 else ''}.\n\n"
                    formatted_report += "💡 **Tip:** Upload a new plant image to add another analysis to your history!"
                    result['final_report'] = formatted_report
        
        # Check if memory error occurred and provide user-friendly message
        logger.info("🔍 DEBUG: Checking for memory error override conditions...")
        logger.info(f"🔍 DEBUG: result.get('status'): {result.get('status')}")
        logger.info(f"🔍 DEBUG: result.get('debug_memory_id'): {result.get('debug_memory_id')}")
        logger.info(f"🔍 DEBUG: 'Memory Error' in final_report: {'Memory Error' in result.get('final_report', '')}")
        
        override_condition = (result.get('status') == 'success' and 
                            result.get('debug_memory_id') is None and 
                            'Memory Error' in result.get('final_report', ''))
        
        logger.info(f"🔍 DEBUG: Override condition met: {override_condition}")
        
        if override_condition:
            logger.info("🔍 DEBUG: OVERRIDING AgentCore response with generic message!")
            logger.info(f"🔍 DEBUG: Original final_report: {result.get('final_report', '')}")
            
            # Override the technical error with user-friendly message
            result['final_report'] = """# 📋 Analysis History

No previous plant analyses found.

This could be because:
- This is your first analysis
- Memory storage is not yet configured
- Previous analyses were done in a different session

💡 **Tip**: Start by analyzing a plant image to create your first analysis record!"""
            
            result['memory_status'] = 'not_configured'
            logger.info("📋 Memory not configured - showing user-friendly message")
            logger.info(f"🔍 DEBUG: New final_report: {result['final_report']}")
        else:
            logger.info("🔍 DEBUG: No override - keeping original AgentCore response")
        
        # Add to chat history
        if result.get('status') == 'success':
            conversation_state['chat_history'].append({
                'type': 'history',
                'timestamp': datetime.now().isoformat(),
                'result': result
            })
            
            logger.info("✅ History retrieval completed successfully")
        
        logger.info(f"🔍 DEBUG: Final result being returned to UI: {json.dumps(result, indent=2)}")
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"❌ History retrieval failed: {e}")
        return jsonify({"error": str(e), "status": "failed"})

@app.route('/api/order', methods=['POST'])
def order_fertilizer():
    """Handle fertilizer ordering - Routes to LangGraph automatic_order state"""
    try:
        logger.info("🛒 Processing fertilizer order request...")
        
        # Get fertilizer from last analysis or use default
        fertilizer = conversation_state.get('recommended_fertilizer', '10-10-10 balanced liquid fertilizer')
        
        # Prepare API payload for fertilizer ordering (triggers automatic_order state)
        payload = {
            "prompt": f"Order fertilizer for my plant",
            "recommended_fertilizer": fertilizer
        }
        
        # Call AgentCore runtime
        result = call_agentcore_runtime(payload)
        
        # Add to chat history
        if result.get('status') == 'success' or result.get('order_status') == 'session_started':
            conversation_state['chat_history'].append({
                'type': 'order',
                'timestamp': datetime.now().isoformat(),
                'result': result
            })
            
            logger.info("✅ Fertilizer order initiated successfully")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"❌ Fertilizer order failed: {e}")
        return jsonify({"error": str(e), "status": "failed"})

@app.route('/api/user-info', methods=['GET'])
@require_auth
def get_user_info():
    """Get current user information"""
    return jsonify({
        'username': session.get('username'),
        'email': session.get('email'),
        'user_id': session.get('user_id'),
        'authenticated': session.get('authenticated', False)
    })


@app.route('/api/chat-state', methods=['GET'])
def get_chat_state():
    """Get current conversation state"""
    return jsonify({
        'has_analysis': bool(conversation_state.get('last_analysis')),
        'recommended_fertilizer': conversation_state.get('recommended_fertilizer'),
        'chat_history_count': len(conversation_state.get('chat_history', [])),
        'runtime_configured': RUNTIME_CONFIGURED,
        'runtime_arn': RUNTIME_ARN,
        'region': AWS_REGION
    })

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "runtime_configured": RUNTIME_CONFIGURED,
        "runtime_arn": RUNTIME_ARN,
        "region": AWS_REGION,
        "account_id": get_account_id() if RUNTIME_CONFIGURED else None,
        "memory_name": MEMORY_NAME,
        "actor_id": ACTOR_ID,
        "session_id": SESSION_ID,
        "timestamp": datetime.now().isoformat()
    })

@app.route('/templates/<filename>')
def serve_template_files(filename):
    """Serve CSS and JS files from templates directory"""
    return send_from_directory('templates', filename)

if __name__ == '__main__':
    print("🚀 Starting Plant Analyzer UI with Authentication...")
    print("=" * 70)
    print("📋 Configuration Summary:")
    print(f"   🔗 Runtime ARN: {RUNTIME_ARN}")
    print(f"   🌍 Region: {AWS_REGION}")
    print(f"   🔐 Cognito User Pool: {COGNITO_USER_POOL_ID}")
    print(f"   🔑 Cognito Client: {COGNITO_CLIENT_ID}")
    print(f"   🆔 Identity Pool: {COGNITO_IDENTITY_POOL_ID}")
    print(f"   🌐 Cognito Domain: {COGNITO_DOMAIN}")
    print(f"   ✅ Status: {'Configured' if RUNTIME_CONFIGURED else 'Not Configured'}")
    print("=" * 70)
    print("🌐 Access the application at:")
    print("   • Landing Page: http://localhost:5000/")
    print("   • Health Check: http://localhost:5000/health")
    print("=" * 70)
    
    # Security Note: host='0.0.0.0' is SAFE in this deployment because:
    # 1. Container runs in private ECS subnet (no direct internet access)
    # 2. Only accessible via ALB in private subnet  
    # 3. ALB only accessible via CloudFront (HTTPS termination + WAF)
    # 4. CloudFront secret header validation prevents direct ALB access
    # 5. Defense in depth: Security groups, NACLs, WAF rules
    #
    # Architecture: Internet -> CloudFront -> ALB -> ECS (0.0.0.0:5000)
    # Direct container access from internet is IMPOSSIBLE.
    # This binding is REQUIRED for Docker container networking in ECS.
    
    app.run(host='0.0.0.0', port=5000, debug=False)
