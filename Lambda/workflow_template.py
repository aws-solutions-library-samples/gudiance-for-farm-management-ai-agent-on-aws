"""
Plant Analysis AgentCore Workflow Template
This template is populated with configuration at runtime from SSM Parameter Store and Secrets Manager
"""

import os, sys, json, requests, random, base64, logging, time, re, uuid
from datetime import datetime
from typing import List, TypedDict, Any
from langchain_core.messages import AnyMessage
from langgraph.graph.message import add_messages
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver
from typing import Annotated
from bedrock_agentcore.runtime import BedrockAgentCoreApp
from bedrock_agentcore.memory import MemoryClient
from bedrock_agentcore_starter_toolkit.operations.gateway.client import GatewayClient
from bedrock_agentcore.tools.browser_client import BrowserClient
import nest_asyncio
from nova_act import NovaAct
import threading
import boto3

# Log package versions at startup
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger("agentcore-memory")

logger.info("=" * 70)
logger.info("PACKAGE VERSIONS:")
try:
    import subprocess
    result = subprocess.run([sys.executable, "-m", "pip", "freeze"], capture_output=True, text=True, timeout=10)
    for line in result.stdout.split('\n'):  # All packages
        if line.strip():
            logger.info(f"  {line}")
except Exception as e:
    logger.error(f"Could not get package versions: {e}")
logger.info("=" * 70)

# Initialize AWS clients for configuration loading
REGION = os.environ.get('AWS_REGION', os.environ.get('AWS_DEFAULT_REGION', 'us-west-2'))
ssm_client = boto3.client('ssm', region_name=REGION)
secrets_client = boto3.client('secretsmanager', region_name=REGION)

def load_runtime_config():
    """
    Load configuration from BOTH SSM parameters:
    - gateway-info: Contains correct Gateway URL and Gateway Cognito credentials
    - app-config: Contains Memory, Runtime, and Region information
    
    Note: gateway-info path includes CloudFormation backend stack suffix, so we search dynamically
    """
    try:
        stack_name = os.environ.get('STACK_NAME', 'plant-advisor-main')
        
        # Find gateway-info parameter dynamically (includes backend stack suffix)
        logging.info(f"Searching for gateway-info parameter with prefix: /plant-advisor/{stack_name}")
        
        try:
            # List parameters to find the correct gateway-info path
            paginator = ssm_client.get_paginator('describe_parameters')
            gateway_param_name = None
            
            for page in paginator.paginate(
                ParameterFilters=[
                    {
                        'Key': 'Name',
                        'Option': 'BeginsWith',
                        'Values': [f'/plant-advisor/{stack_name}']
                    }
                ]
            ):
                for param in page['Parameters']:
                    if 'gateway-info' in param['Name']:
                        gateway_param_name = param['Name']
                        break
                if gateway_param_name:
                    break
            
            if not gateway_param_name:
                raise RuntimeError(f"gateway-info parameter not found with prefix /plant-advisor/{stack_name}")
            
            logging.info(f"✅ Found Gateway config at: {gateway_param_name}")
            
        except Exception as e:
            logging.error(f"Failed to find gateway-info parameter: {e}")
            raise
        
        # Load Gateway configuration
        gateway_response = ssm_client.get_parameter(Name=gateway_param_name)
        gateway_data = json.loads(gateway_response['Parameter']['Value'])
        
        # Parse Gateway Cognito info from nested JSON
        gateway_cognito = json.loads(gateway_data['cognito_info'])['client_info']
        
        # Load App configuration (has Memory, Runtime info)
        # Use main stack name (not backend stack name) for app-config
        main_stack_name = 'plant-advisor-main'
        app_param_name = f'/plant-advisor/{main_stack_name}/app-config'
        logging.info(f"Loading App config from: {app_param_name}")
        
        app_response = ssm_client.get_parameter(Name=app_param_name)
        app_data = json.loads(app_response['Parameter']['Value'])
        
        # Build complete configuration using correct values from each source
        runtime_config = {
            # Region from app-config
            'region': app_data['REGION'],
            
            # Gateway values from gateway-info (correct!)
            'gateway_id': gateway_data['gateway_id'],
            'gateway_url': gateway_data['gateway_url'],
            
            # Memory values from app-config
            'memory_id': app_data['MEMORY_NAME'],
            'memory_role_arn': app_data['MEMORY_ROLE_ARN'],
            
            # Gateway Cognito from gateway-info (correct for authentication!)
            'client_id': gateway_cognito['client_id'],
            'client_secret': gateway_cognito['client_secret'],
            'scopes': gateway_cognito['scope'],
            'token_endpoint': gateway_cognito['token_endpoint'],
            'user_pool_id': gateway_cognito['user_pool_id'],
            'region_from_pool': gateway_cognito['user_pool_id'].split('_')[0]
        }
        
        logging.info("✅ Configuration loaded successfully from gateway-info and app-config")
        logging.info(f"Gateway URL: {runtime_config['gateway_url']}")
        logging.info(f"Gateway Cognito User Pool: {runtime_config['user_pool_id']}")
        
        return runtime_config
        
    except Exception as e:
        logging.error(f"❌ Error loading runtime configuration: {e}")
        raise RuntimeError(f"Failed to load configuration from SSM parameters: {e}")

# Load configuration at module initialization
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger("agentcore-memory")

logger.info("Loading runtime configuration...")
runtime_config = load_runtime_config()

# Set environment variables for AWS services
os.environ['AWS_DEFAULT_REGION'] = runtime_config['region']
os.environ['AWS_REGION'] = runtime_config['region']

# Build Cognito configuration
COGNITO_INFO = {
    "client_id": runtime_config['client_id'],
    "client_secret": runtime_config['client_secret'],
    "user_pool_id": runtime_config['user_pool_id'],
    "region": runtime_config['region_from_pool']
}

COGNITO_INFO_RAW = {
    "client_id": runtime_config['client_id'],
    "client_secret": runtime_config['client_secret'],
    "user_pool_id": runtime_config['user_pool_id'],
    "region": runtime_config['region_from_pool'],
    "scope": runtime_config['scopes'],
    "token_endpoint": runtime_config['token_endpoint']
}

# Initialize AgentCore components
app = BedrockAgentCoreApp()

REGION = runtime_config['region']
GATEWAY_ID = runtime_config['gateway_id']
GATEWAY_URL = runtime_config['gateway_url']
MEMORY_ID = runtime_config['memory_id']
MEMORY_ROLE_ARN = runtime_config['memory_role_arn']

client = GatewayClient(region_name=REGION)
memory_client = MemoryClient(region_name=REGION)

ACTOR_ID = "user_123"
SESSION_ID = "plant_analysis_session_00001_demo"

class PlantAnalysisState(TypedDict):
    messages: Annotated[List[AnyMessage], add_messages]
    prompt: str           
    query_type: str
    image_path: str
    image_data: str
    plant_detection: dict
    health_issues: str
    expert_advice: str
    recommended_fertilizer: str
    web_search_results: str
    final_report: str
    memory_status: str    
    order_status: str
    live_session_url: str 
    message: str          

def call_mcp_tool(tool_name: str, arguments: dict, bearer_token: str):
    headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {bearer_token}'}
    payload = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments}
    }
    response = requests.post(GATEWAY_URL, headers=headers, json=payload, timeout=30)
    return response.json()

def parse_mcp_response(result):
    try:
        if 'result' in result and 'content' in result['result']:
            content = result['result']['content'][0]['text']
            outer_json = json.loads(content)
          
            if 'statusCode' in outer_json and 'body' in outer_json:
                if outer_json['statusCode'] == 200:
                    return json.loads(outer_json['body'])
          
            return outer_json
        return None
    except Exception as e:
        print(f"Parse error: {str(e)}")
        return None

def create_plant_workflow():
    workflow = StateGraph(PlantAnalysisState)
    
    def detect_plant(state: PlantAnalysisState) -> dict:
        try:
            bearer_token = client.get_access_token_for_cognito(COGNITO_INFO_RAW)
        except Exception as token_error:
            raise token_error
        image_data = state.get('image_data', '')
                          
        try:
            result = call_mcp_tool("plant-detection-target___plant_detection_tool", {
                "image_data": image_data
            }, bearer_token)
                                  
            parsed_result = parse_mcp_response(result)
                                  
            if parsed_result:
                plant_name = parsed_result.get("plant_name", "unknown")
                health_issues = parsed_result.get("health_issues", "")
                print(f"DEBUG - Extracted plant_name: {plant_name}, health_issues: {health_issues}")
                return {
                    "plant_detection": {"plant_type": plant_name},
                    "health_issues": health_issues
                }
            else:
                print("DEBUG - No parsed result from MCP response")
        except Exception as e:
            print(f"DEBUG - Plant detection error: {str(e)}")
            import traceback
            print(f"DEBUG - Traceback: {traceback.format_exc()}")
        
        return {"plant_detection": {"plant_type": "error"}, "health_issues": "Detection failed"}
    
    def entry_router(state: PlantAnalysisState) -> dict:
        prompt = state.get("prompt", "")
        image_data = state.get("image_data", "")

        if prompt:
            history_keywords = ["show me", "previous", "compare", "history", "analyses", "month", "last time"]
            if any(keyword in prompt.lower() for keyword in history_keywords):
                return {"next": "retrieve_memory"}

        if prompt:
            order_keywords = ["order", "buy", "purchase", "cart", "checkout", "fertilizer"]
            if any(keyword in prompt.lower() for keyword in order_keywords):
                return {"next": "automatic_order"}

        if image_data:
            return {"next": "detect_plant"}

        return {"next": "END"}

    def analysis_router(state: PlantAnalysisState) -> str:
        plant_detection = state.get("plant_detection", {})
        plant_name = plant_detection.get("plant_type", "").lower()
        health_issues = state.get("health_issues", "").lower()

        if not plant_name or plant_name == "error":
            return "END"

        critical_keywords = ["severe", "dying", "critical", "emergency"]
        if any(keyword in health_issues for keyword in critical_keywords):
            return "urgent_consultation"

        return "expert_consultation"
      
    def plant_care_agent(state: PlantAnalysisState) -> dict:
        bearer_token = client.get_access_token_for_cognito(COGNITO_INFO_RAW)
        plant_info = state.get('plant_detection', {})
        health_status = state.get('health_issues', '')
        plant_name = plant_info.get('plant_type', 'unknown plant')
        
        try:
            result = call_mcp_tool("plant-care-target___plant_care_tool", {
                "plant_name": plant_name,
                "health_status": health_status
            }, bearer_token)
            
            parsed_result = parse_mcp_response(result)
            
            if parsed_result and 'expert_advice' in parsed_result:
                advice = parsed_result['expert_advice']
                fertilizer = parsed_result.get('recommended_fertilizer', 'All Purpose Plant Fertilizer')
                return {'expert_advice': advice, 'recommended_fertilizer': fertilizer}
        except Exception as e:
            print(f"DEBUG - Plant care error: {str(e)}")
        
        return {'expert_advice': 'Plant care advice unavailable'}
    
    def web_search_agent(state: PlantAnalysisState) -> dict:
        bearer_token = client.get_access_token_for_cognito(COGNITO_INFO_RAW)
        plant_info = state.get('plant_detection', {})
        health_status = state.get('health_issues', '')
        plant_name = plant_info.get('plant_type', 'unknown plant')

        logger.info(f"🔍 Web searching for: {plant_name}")

        try:
            result = call_mcp_tool("plant-web-search-target___plant_web_search_tool", {
            "plant_name": plant_name,
            "health_status": health_status
            }, bearer_token)

            parsed_result = parse_mcp_response(result)

            if parsed_result:
                search_results = parsed_result.get('web_search_results', str(parsed_result))
                logger.info(f"✅ Web search completed ({len(search_results)} chars)")
                return {'web_search_results': search_results}

        except Exception as e:
            logger.error(f"❌ Web search error: {e}")

        return {'web_search_results': 'Web search unavailable'}

    def expert_consultation_agent(state: PlantAnalysisState) -> dict:
        care_result = plant_care_agent(state)

        if care_result.get('expert_advice') and 'unavailable' not in care_result.get('expert_advice', ''):
            return care_result

        web_result = web_search_agent(state)
        return {
            'expert_advice': web_result.get('web_search_results', 'No advice available'),
            'web_search_results': web_result.get('web_search_results', '')
        }

    def urgent_consultation_agent(state: PlantAnalysisState) -> dict:
        care_result = plant_care_agent(state)
        web_result = web_search_agent(state)

        expert_advice = care_result.get('expert_advice', '')
        web_search_results = web_result.get('web_search_results', '')

        combined_advice = f"""**Expert Care Advice:**
        {expert_advice}

        **Additional Web Research:**
        {web_search_results}"""

        return {
        'expert_advice': combined_advice,
        'web_search_results': web_search_results
        }

    def write_report(state: PlantAnalysisState) -> dict:
        plant_info = state.get("plant_detection", {})
        health_issues = state.get("health_issues", "")
        expert_advice = state.get("expert_advice", "")
        
        report = f"""# Plant Analysis Report
## Detection Results
- Plant Type: {plant_info.get('plant_type', 'Unknown')}
- Health Assessment: {health_issues}
## Expert Recommendations
{expert_advice}
"""                 
        return {"final_report": report}
    
    def retrieve_memory_agent(state: PlantAnalysisState) -> dict:
        try:
            if not memory_client:
                return {
                    "final_report": "# Memory Error\\nMemory client not initialized",
                    "memory_status": "error"
                }

            events = memory_client.list_events(
                memory_id=MEMORY_ID,
                actor_id=ACTOR_ID,
                session_id=SESSION_ID,
                max_results=10
            )

            if events:
                history_summary = "# Plant Analysis History\\n\\n"
                for i, event in enumerate(events, 1):
                    timestamp = event.get('eventTimestamp', 'Unknown time')
                    if hasattr(timestamp, 'strftime'):
                        formatted_time = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                    else:
                        formatted_time = str(timestamp)
                    
                    payload = event.get('payload', [])
                    plant_info = "Unknown plant"
                    advice_summary = "No advice available"
                    
                    for msg in payload:
                        if 'conversational' in msg:
                            content = msg['conversational']['content']['text']
                            if msg['conversational']['role'] == 'USER':
                                plant_info = content.replace('Plant analysis for ', '')
                            elif msg['conversational']['role'] == 'ASSISTANT':
                                advice_summary = content.strip()
                                advice_summary = advice_summary.replace('\\n', ' ').replace('\n', ' ')
                                if len(advice_summary) > 300:
                                    advice_summary = advice_summary[:300] + "..."
                    
                    history_summary += f"**{i}. {formatted_time}**\\n"
                    history_summary += f"   Plant: {plant_info}\\n"
                    history_summary += f"   Advice: {advice_summary}\\n\\n"

            else:
                history_summary = "# Plant Analysis History\\n\\nNo previous analyses found."

            return {
                "final_report": history_summary,
                "memory_status": "retrieved"
            }
        except Exception as e:
            return {
                "final_report": f"# Memory Error\\n\\nCould not retrieve history: {str(e)}",
                "memory_status": "error"
            }

    def save_memory_agent(state: PlantAnalysisState) -> dict:
        try:
            plant_info = state.get("plant_detection", {})
            health_issues = state.get("health_issues", "")
            expert_advice = state.get("expert_advice", "")
            conversation = [
                (f"Plant analysis for {plant_info.get('plant_type', 'unknown plant')}", "USER"),
                (f"Plant: {plant_info.get('plant_type')}\\nHealth: {health_issues}\\nAdvice: {expert_advice}", "ASSISTANT")
            ]
            memory_client.save_conversation(
                memory_id=MEMORY_ID,
                actor_id=ACTOR_ID,
                session_id=SESSION_ID,
                messages=conversation
            )
            current_report = state.get("final_report", "")
            enhanced_report = current_report + "\\n\\n*Analysis saved to memory*"
            
            return {
                "final_report": enhanced_report,
                "memory_status": "saved"
            }
        except Exception as e:
            current_report = state.get("final_report", "")
            enhanced_report = current_report + f"\\n\\n*Memory save failed: {str(e)}*"
            return {
                "final_report": enhanced_report,
                "memory_status": f"save_failed: {str(e)}"
            }
  
    def get_nova_act_api_key(secret_name: str = None, region: str = None) -> str:
        """
        Retrieve Nova-Act API key from Secrets Manager.
        Region defaults to Lambda's region if not specified.
        Secret name defaults to stack-aware pattern matching CloudFormation.
        """
        if region is None:
            region = os.environ.get('AWS_REGION', os.environ.get('AWS_DEFAULT_REGION', 'us-east-1'))
        
        # Build secret name with stack suffix (matches CloudFormation pattern)
        if secret_name is None:
            stack_name = os.environ.get('STACK_NAME', 'plant-advisor-main')
            secret_name = f'nova-act-api-key-{stack_name}'
        
        try:
            session = boto3.session.Session()
            client = session.client(service_name='secretsmanager', region_name=region)
            
            logger.info(f"🔐 Retrieving Nova-Act API key from: {secret_name}")
            response = client.get_secret_value(SecretId=secret_name)
            secret_dict = json.loads(response['SecretString'])
            
            api_key = secret_dict.get('nova_act_api_key')
            if not api_key:
                raise ValueError("nova_act_api_key not found in secret")
            
            logger.info("✅ Nova-Act API key retrieved successfully")
            return api_key
            
        except Exception as exc:
            logger.warning(f"⚠️ Nova-Act API key not available from {secret_name}: {str(exc)}")
            logger.warning("⚠️ Automatic ordering feature will be disabled")
            return "NOT_CONFIGURED"

    def monitor_login_and_continue_checkout(ws_url, headers, product_name, max_wait_minutes=10) -> dict:
        logger.info(f"🔍 Creating browser session for login monitoring and checkout...")
        max_checks = (max_wait_minutes * 60) // 5
        
        login_check_prompt = """
Check login status on current Amazon page:

INSTRUCTIONS:
1. Look at the current Amazon page you are on
2. Do NOT refresh the page - just observe the current state
3. Look for signs of successful login:
    - Account name appearing in top right corner (like "Hello, [Name]")
    - User account dropdown or menu
    - Any personalized content indicating user is logged in
4. Once you see the user's name or account info, return "LOGIN_COMPLETE"
5. If you still see "Hello, Sign in" or just "Sign In", return "LOGIN_PENDING"

IMPORTANT: 
- Do NOT refresh or navigate to any other page
- Just observe the current page state
- Do NOT enter any credentials yourself
- Do NOT click any login buttons or fields
- Look specifically for the user's name in the top navigation area

Return "LOGIN_COMPLETE" when you can see the user is logged in.
"""
        
        checkout_prompt = f"""
Complete Amazon checkout for fertilizer product: {product_name}

CURRENT STATE: You are on Amazon homepage and user should be logged in

CHECKOUT STEPS:
1. You are already on Amazon's homepage (https://www.amazon.com/ref=ap_frn_logo)
2. Verify you can see the user's name in the top right (confirming login)
3. Find the search box and search for: {product_name}
4. Press Enter or click search button
5. Look for organic/natural fertilizer products in the results
6. Click on the first relevant fertilizer product from results
7. On product page, click 'Add to Cart'
8. Handle any pop-ups by declining additional offers
9. Go to cart (click cart icon in top right)
10. Click 'Proceed to checkout'
11. Review order details and complete the purchase

Work step by step and handle any unexpected elements.
Focus on finding fertilizer products that match the plant analysis recommendations.
Continue from the current homepage in this same browser tab.
"""
        
        try:
            with NovaAct(
                cdp_endpoint_url=ws_url,
                cdp_headers=headers,
                preview={"playwright_actuation": True},
                nova_act_api_key=get_nova_act_api_key(region=REGION), 
                starting_page="https://www.amazon.com/ref=ap_frn_logo",
            ) as nova_act_session:
                logger.info(f"✅ Browser session created for monitoring and checkout")
                
                login_detected = False
                for check_num in range(1, max_checks + 1):
                    logger.info(f"Check {check_num}/{max_checks}: Checking login status...")     
                    if check_num > 1:
                        time.sleep(2)
                    try:
                        result = nova_act_session.act(login_check_prompt)
                        login_status = result.response
                        logger.info(f"Login status: {login_status}")
                        
                        if "LOGIN_COMPLETE" in login_status:
                            logger.info("✅ User name detected - login complete!")
                            login_detected = True
                            break
                    except Exception as e:
                        logger.error(f"Login check error: {str(e)[:100]}...")
                    
                    if check_num < max_checks:
                        logger.info(f"⏳ No user name visible yet, waiting 5 seconds... ({check_num * 5}s elapsed)")
                        time.sleep(5)
                    else:
                        logger.warning(f"⚠️ Maximum wait time reached ({max_wait_minutes} minutes)")
                        logger.warning("Proceeding with checkout anyway...")
                        break
                
                logger.info("🛒 Continuing with fertilizer checkout in the same browser tab...")
                logger.info("👀 Watch the checkout process continue in the same window!")
                time.sleep(3)
                
                try:  
                    checkout_result = nova_act_session.act(checkout_prompt)
                    logger.info(f"Checkout result: {checkout_result.response}")
                    
                    return {
                        'login_detected': login_detected,
                        'checkout_result': checkout_result.response,
                        'status': 'completed'
                    }
                except Exception as checkout_error:
                    logger.error(f"⚠️ Checkout error: {str(checkout_error)[:100]}...")
                    return {
                        'login_detected': login_detected,
                        'checkout_result': f'Checkout initiated for {product_name}. Error: {str(checkout_error)[:100]}',
                        'status': 'error'
                    }
        except Exception as e:
            logger.error(f"❌ Error in monitoring/checkout session: {str(e)[:100]}...")
            return {
                'login_detected': False,
                'checkout_result': f'Session error: {str(e)[:100]}',
                'status': 'error'
            }

    class AsyncBrowserSessionManager:
        def __init__(self, region: str):
            self.region = region
            self.browser_client = None
            self.session_id = None
            self.ws_url = None
            self.headers = None
        
        def get_or_create_session(self):
            self.browser_client = BrowserClient(self.region)
            
            self.session_id = self.browser_client.start(
                identifier="aws.browser.v1",
                name=f"plant-analysis-{uuid.uuid4().hex[:8]}",
                session_timeout_seconds=1800
            )
            
            self.ws_url, self.headers = self.browser_client.generate_ws_headers()
            logger.info(f"✅ WebSocket credentials generated")     
            
            session_match = re.search(r'/sessions/([A-Z0-9]+)', self.ws_url)
            if session_match:
                self.session_id = session_match.group(1)
                logger.info(f"✅ Enhanced session created: {self.session_id}")
            
            return self.browser_client, self.ws_url, self.headers, self.session_id
        
        def cleanup(self):
            self.session_id = None
            self.browser_client.stop()

    def automatic_order_agent(state: PlantAnalysisState) -> dict:
        """Automated fertilizer ordering using Nova Act and Amazon.com"""
        
        # Get fertilizer from memory or use default
        fertilizer_product = '10-10-10 balanced liquid fertilizer'
        
        try:
            events = memory_client.list_events(
                memory_id=MEMORY_ID,
                actor_id=ACTOR_ID,
                session_id=SESSION_ID,
                max_results=1
            )
            
            if events:
                payload = events[0].get('payload', [])
                for msg in payload:
                    if (msg.get('conversational', {}).get('role') == 'ASSISTANT'):
                        content = msg['conversational']['content']['text']
                        if 'Fertilizer: ' in content:
                            fertilizer_product = content.split('Fertilizer: ')[1].strip()
                            break
                    break
        except Exception as e:
            logger.error(f"Failed to get fertilizer from memory: {e}")
        
        logger.info(f"🛒 Starting Amazon automation for: {fertilizer_product}")
        
        try:
            # Verify Nova Act API key is available
            api_key = get_nova_act_api_key(region=REGION)
            if api_key == "NOT_CONFIGURED":
                return {
                    'order_status': 'error',
                    'error': 'Nova Act API key not configured',
                    'message': 'Please configure Nova Act API key in Secrets Manager'
                }
            
            # Create browser session
            session_manager = AsyncBrowserSessionManager(REGION)
            browser_client, ws_url, headers, session_id = session_manager.get_or_create_session()
            
            if not session_id:
                return {
                    'order_status': 'error',
                    'error': 'Failed to create browser session'
                }
            
            # Build live viewer URL
            live_url = f"https://{REGION}.console.aws.amazon.com/bedrock-agentcore/builtInTools/browser/aws.browser.v1/session/{session_id}#"
            logger.info(f"🌐 Browser viewer URL: {live_url}")
            
            # Start Nova Act workflow in background thread
            def fertilizer_workflow():
                try:
                    logger.info("🚀 Starting Nova Act workflow...")
                    
                    # Single continuous NovaAct session
                    with NovaAct(
                        cdp_endpoint_url=ws_url,
                        cdp_headers=headers,
                        preview={"playwright_actuation": True},
                        nova_act_api_key=api_key,
                        starting_page="https://www.amazon.com",
                    ) as nova_session:
                        
                        # Give page time to load
                        time.sleep(3)
                        logger.info("✅ Browser loaded Amazon.com")
                        
                        # Step 1: Check login status
                        login_check = """
Look at the Amazon page. Check if user is logged in.
- If you see "Hello, Sign in" or "Sign In" in top right → Click it to open login page
- If you see "Hello, [Name]" with actual user name → Return "ALREADY_LOGGED_IN"

Click sign-in button if user is not logged in.
"""
                        
                        check_result = nova_session.act(login_check)
                        logger.info(f"Login check: {check_result.response}")
                        
                        # Step 2: Wait for user to login (if needed)
                        if "ALREADY_LOGGED_IN" not in check_result.response:
                            logger.info("⏳ Waiting for user to complete login...")
                            logger.info("💡 User should use the AWS Console browser viewer to login")
                            
                            # Monitor for login completion (max 10 minutes)
                            login_detected = False
                            for attempt in range(120):  # 120 * 5 = 600 seconds = 10 min
                                time.sleep(5)
                                
                                monitor = """
Check if user is now logged in to Amazon.
Look at top right corner:
- If you see user's name (like "Hello, John") → Return "LOGIN_COMPLETE"
- If you still see "Hello, Sign in" → Return "WAITING"

Just check and return status, don't click anything.
"""
                                
                                status = nova_session.act(monitor)
                                logger.info(f"Login monitor [{attempt+1}/120]: {status.response}")
                                
                                if "LOGIN_COMPLETE" in status.response:
                                    login_detected = True
                                    logger.info("✅ User successfully logged in!")
                                    break
                            
                            if not login_detected:
                                logger.warning("⚠️ Login timeout - proceeding anyway")
                        
                        # Step 3: Search and order fertilizer
                        logger.info(f"🛒 Starting checkout for: {fertilizer_product}")
                        
                        checkout = f"""
Complete Amazon checkout for: {fertilizer_product}

Steps:
1. Find the search box on Amazon homepage
2. Type: {fertilizer_product}
3. Press Enter or click Search button
4. Wait for search results
5. Click on the FIRST relevant organic/natural fertilizer product
6. On product page, click "Add to Cart" button
7. Click cart icon in top right
8. Click "Proceed to checkout"
9. Review order details

Work step-by-step. Handle pop-ups by declining extras.
Focus on finding organic fertilizers that match the plant needs.
"""
                        
                        result = nova_session.act(checkout)
                        logger.info(f"✅ Checkout completed: {result.response}")
                        
                        # Keep browser open for user review
                        logger.info("🖥️ Keeping browser open for 90 seconds...")
                        time.sleep(90)
                        logger.info("✅ Workflow complete!")
                        
                except Exception as e:
                    logger.error(f"❌ Workflow error: {str(e)}")
                    import traceback
                    logger.error(f"Traceback: {traceback.format_exc()}")
            
            # Start workflow in background thread
            workflow_thread = threading.Thread(
                target=fertilizer_workflow,
                daemon=True,
                name="NovaActFertilizerWorkflow"
            )
            workflow_thread.start()
            
            # Give thread a moment to start
            time.sleep(0.5)
            
            # Return success with viewer URL
            return {
                'order_status': 'session_started',
                'live_session_url': live_url,
                'message': 'Browser automation started. Open the viewer URL to watch and complete login if needed.',
                'recommended_fertilizer': fertilizer_product
            }
            
        except Exception as e:
            logger.error(f"❌ Error in automatic_order_agent: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return {
                'order_status': 'error',
                'error': str(e),
                'message': 'Failed to start browser automation'
            }

    # Add nodes
    workflow.add_node("entry_router", entry_router)
    workflow.add_node("detect_plant", detect_plant)
    workflow.add_node("urgent_consultation", urgent_consultation_agent)
    workflow.add_node("expert_consultation", expert_consultation_agent)
    workflow.add_node("write_report", write_report)
    workflow.add_node("retrieve_memory", retrieve_memory_agent)
    workflow.add_node("save_memory", save_memory_agent)
    workflow.add_node("automatic_order", automatic_order_agent)

    # Build workflow
    workflow.set_entry_point("entry_router")
    
    workflow.add_conditional_edges(
        "entry_router",
        lambda state: entry_router(state)["next"],
        {
            "detect_plant": "detect_plant",
            "retrieve_memory": "retrieve_memory",
            "automatic_order": "automatic_order",
            "END": END
        }
    )
    
    workflow.add_conditional_edges(
        "detect_plant",
        analysis_router,
        {
            "urgent_consultation": "urgent_consultation",
            "expert_consultation": "expert_consultation",
            "END": END
        }
    )
    
    workflow.add_edge("expert_consultation", "write_report")
    workflow.add_edge("urgent_consultation", "write_report")
    workflow.add_edge("write_report", "save_memory")
    workflow.add_edge("save_memory", END)
    workflow.add_edge("automatic_order", END)
    workflow.add_edge("retrieve_memory", END)
    
    return workflow.compile(checkpointer=MemorySaver())

langgraph_workflow = create_plant_workflow()

@app.entrypoint
def invoke(payload):
    log_payload = payload.copy()
    if 'image_data' in log_payload and log_payload['image_data']:
        log_payload['image_data'] = f"{log_payload['image_data'][:50]}... ({len(log_payload['image_data'])} chars)"
    
    print(f"📥 Received payload: {log_payload}")
    prompt = payload.get("prompt", "")
    image_path = payload.get("image_path", "")
    image_data = payload.get("image_data", "")
    
    history_keywords = ["show me", "previous", "compare", "history", "analyses", "month", "last time"]
    is_history_query = any(keyword in prompt.lower() for keyword in history_keywords) if prompt else False
    
    order_keywords = ["order", "buy", "purchase", "cart", "checkout", "fertilizer"]
    is_ordering_query = any(keyword in prompt.lower() for keyword in order_keywords) if prompt else False
    
    if not is_history_query and not is_ordering_query and not image_path and not image_data:
        return {"error": "No image_path or image_data provided for plant analysis", "status": "failed"}
    
    initial_state = {
        "messages": [],
        "prompt": prompt,
        "query_type": "history" if is_history_query else ("order" if is_ordering_query else "analysis"),
        "image_path": image_path or "from_image_data",
        "image_data": image_data,
        "plant_detection": {},
        "health_issues": "",
        "expert_advice": "",
        "recommended_fertilizer": "",
        "web_search_results": "",
        "final_report": "",
        "memory_status": "",
        "order_status": "",
        "live_session_url": "",
        "message": ""
    }
    
    config = {"configurable": {"thread_id": f"agentcore_{random.randint(1000, 9999)}"}}
    
    try:
        final_state = langgraph_workflow.invoke(initial_state, config)
        
        return {
            "plant_type": final_state.get('plant_detection', {}).get('plant_type', 'Unknown'),
            "health_issues": final_state.get('health_issues', ''),
            "expert_advice": final_state.get('expert_advice', ''),
            "recommended_fertilizer": final_state.get('recommended_fertilizer', 'All Purpose Plant Fertilizer'),
            "web_search_results": final_state.get('web_search_results', ''),
            "final_report": final_state.get('final_report', ''),
            "memory_status": final_state.get('memory_status', ''),
            "order_status": final_state.get('order_status', ''),
            "live_session_url": final_state.get('live_session_url', ''),
            "message": final_state.get('message', ''),
            "debug_memory_id": MEMORY_ID,
            "debug_actor_id": ACTOR_ID,
            "debug_session_id": SESSION_ID,
            "status": "success"
        }
    except Exception as e:
        print(f"Workflow error: {str(e)}")
        return {"error": str(e), "status": "failed"}

if __name__ == "__main__":
    app.run()
