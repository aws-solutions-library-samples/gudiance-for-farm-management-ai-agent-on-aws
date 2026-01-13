"""
AgentCore Runtime Custom Resource 
"""

import json, urllib3, sys, os, tempfile, shutil
from typing import Dict, Any
from dataclasses import dataclass

@dataclass
class RuntimeConfig:
    """Configuration for AgentCore Runtime"""
    gateway_id: str
    gateway_url: str
    memory_id: str
    memory_role_arn: str
    runtime_role_arn: str
    region: str
    client_id: str
    client_secret: str
    user_pool_id: str
    region_from_pool: str
    cognito_info_raw: dict

# PackageManager class removed - using Lambda Layer instead

class RuntimeCleaner:
    """Handles cleanup of AgentCore resources"""
    def __init__(self, boto3_client, region: str):
        self.boto3 = boto3_client
        self.region = region
    
    def cleanup_and_delete(self, runtime_id: str):
        if runtime_id:
            print(f"Attempting to delete runtime: {runtime_id}")
            
            # Delete CodeBuild projects
            try:
                codebuild = self.boto3.client('codebuild', region_name=self.region)
                projects = codebuild.list_projects()['projects']
                for project in projects:
                    if 'AmazonBedrockAgentCoreSDKCodeBuild' in project:
                        print(f"Deleting CodeBuild project: {project}")
                        codebuild.delete_project(name=project)
            except Exception as cb_error:
                print(f"CodeBuild cleanup error: {str(cb_error)}")
            
            # Delete runtime
            try:
                bedrock_client = self.boto3.client('bedrock-agentcore-control', region_name=self.region)
                bedrock_client.delete_agent_runtime(agentRuntimeId=runtime_id)
                print(f"Successfully deleted runtime: {runtime_id}")
            except Exception as rt_error:
                print(f"Runtime deletion failed: {str(rt_error)}")

class WorkflowCodeGenerator:
    """Loads and uses the external workflow template"""
    def __init__(self, config: RuntimeConfig):
        self.config = config
    
    def load_workflow_template(self) -> str:
        """Load workflow from external template file"""
        # Read the workflow template from the same directory
        template_path = os.path.join(os.path.dirname(__file__), 'workflow_template.py')
        
        if not os.path.exists(template_path):
            raise FileNotFoundError(f"Workflow template not found at: {template_path}")
        
        with open(template_path, 'r') as f:
            template_content = f.read()
        
        print(f"Loaded workflow template from: {template_path}")
        return template_content
    
    def generate_complete_workflow(self) -> str:
        """Load the workflow template - configuration will be loaded at runtime from SSM/Secrets"""
        # Simply return the template content
        # The template now loads its own configuration from SSM Parameter Store and Secrets Manager
        return self.load_workflow_template()
    
    def _generate_embedded_workflow_deprecated(self) -> str:
        """
        DEPRECATED: Old method that embedded config at deployment time
        Kept for reference only - not used anymore
        """
        return f'''
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

# Set up environment variables for AWS services
os.environ['AWS_DEFAULT_REGION'] = '{self.config.region}'
os.environ['AWS_REGION'] = '{self.config.region}'

COGNITO_INFO = {{
    "client_id": "{self.config.client_id}",
    "client_secret": "{self.config.client_secret}",
    "user_pool_id": "{self.config.user_pool_id}",
    "region": "{self.config.region_from_pool}"
}}

COGNITO_INFO_RAW = {repr(self.config.cognito_info_raw)}

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger("agentcore-memory")

app = BedrockAgentCoreApp()

REGION = '{self.config.region}'
GATEWAY_ID = '{self.config.gateway_id}'
GATEWAY_URL = '{self.config.gateway_url}'
MEMORY_ID = '{self.config.memory_id}'
MEMORY_ROLE_ARN = '{self.config.memory_role_arn}'

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
    headers = {{'Content-Type': 'application/json', 'Authorization': f'Bearer {{bearer_token}}'}}
    payload = {{
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {{"name": tool_name, "arguments": arguments}}
    }}
    response = requests.post(GATEWAY_URL, headers=headers, json=payload)
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
        print(f"Parse error: {{str(e)}}")
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
            result = call_mcp_tool("plant-detection-target___plant_detection_tool", {{
                "image_data": image_data
            }}, bearer_token)
                                  
            parsed_result = parse_mcp_response(result)
                                  
            if parsed_result:
                plant_name = parsed_result.get("plant_name", "unknown")
                health_issues = parsed_result.get("health_issues", "")
                print(f"DEBUG - Extracted plant_name: {{plant_name}}, health_issues: {{health_issues}}")
                return {{
                    "plant_detection": {{"plant_type": plant_name}},
                    "health_issues": health_issues
                }}
            else:
                print("DEBUG - No parsed result from MCP response")
        except Exception as e:
            print(f"DEBUG - Plant detection error: {{str(e)}}")
            import traceback
            print(f"DEBUG - Traceback: {{traceback.format_exc()}}")
        
        return {{"plant_detection": {{"plant_type": "error"}}, "health_issues": "Detection failed"}}
    
    def entry_router(state: PlantAnalysisState) -> dict:
        prompt = state.get("prompt", "")
        image_data = state.get("image_data", "")

        if prompt:
            history_keywords = ["show me", "previous", "compare", "history", "analyses", "month", "last time"]
            if any(keyword in prompt.lower() for keyword in history_keywords):
                return {{"next": "retrieve_memory"}}

        if prompt:
            order_keywords = ["order", "buy", "purchase", "cart", "checkout", "fertilizer"]
            if any(keyword in prompt.lower() for keyword in order_keywords):
                return {{"next": "automatic_order"}}

        if image_data:
            return {{"next": "detect_plant"}}

        return {{"next": "END"}}

    def analysis_router(state: PlantAnalysisState) -> str:
        plant_detection = state.get("plant_detection", {{}})
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
        plant_info = state.get('plant_detection', {{}})
        health_status = state.get('health_issues', '')
        plant_name = plant_info.get('plant_type', 'unknown plant')
        
        try:
            result = call_mcp_tool("plant-care-target___plant_care_tool", {{
                "plant_name": plant_name,
                "health_status": health_status
            }}, bearer_token)
            
            parsed_result = parse_mcp_response(result)
            
            if parsed_result and 'expert_advice' in parsed_result:
                advice = parsed_result['expert_advice']
                fertilizer = parsed_result.get('recommended_fertilizer', 'All Purpose Plant Fertilizer')
                return {{'expert_advice': advice, 'recommended_fertilizer': fertilizer}}
        except Exception as e:
            print(f"DEBUG - Plant care error: {{str(e)}}")
        
        return {{'expert_advice': 'Plant care advice unavailable'}}
    
    def web_search_agent(state: PlantAnalysisState) -> dict:
        bearer_token = client.get_access_token_for_cognito(COGNITO_INFO_RAW)
        plant_info = state.get('plant_detection', {{}})
        health_status = state.get('health_issues', '')
        plant_name = plant_info.get('plant_type', 'unknown plant')

        logger.info(f"🔍 Web searching for: {{plant_name}}")

        try:
            result = call_mcp_tool("plant-web-search-target___plant_web_search_tool", {{
            "plant_name": plant_name,
            "health_status": health_status
            }}, bearer_token)

            parsed_result = parse_mcp_response(result)

            if parsed_result:
                search_results = parsed_result.get('web_search_results', str(parsed_result))
                logger.info(f"✅ Web search completed ({{len(search_results)}} chars)")
                return {{'web_search_results': search_results}}

        except Exception as e:
            logger.error(f"❌ Web search error: {{e}}")

        return {{'web_search_results': 'Web search unavailable'}}

    def expert_consultation_agent(state: PlantAnalysisState) -> dict:
        care_result = plant_care_agent(state)

        if care_result.get('expert_advice') and 'unavailable' not in care_result.get('expert_advice', ''):
            return care_result

        web_result = web_search_agent(state)
        return {{
            'expert_advice': web_result.get('web_search_results', 'No advice available'),
            'web_search_results': web_result.get('web_search_results', '')
        }}

    def urgent_consultation_agent(state: PlantAnalysisState) -> dict:
        care_result = plant_care_agent(state)
        web_result = web_search_agent(state)

        expert_advice = care_result.get('expert_advice', '')
        web_search_results = web_result.get('web_search_results', '')

        combined_advice = f"""**Expert Care Advice:**
        {{expert_advice}}

        **Additional Web Research:**
        {{web_search_results}}"""

        return {{
        'expert_advice': combined_advice,
        'web_search_results': web_search_results
        }}

    def write_report(state: PlantAnalysisState) -> dict:
        plant_info = state.get("plant_detection", {{}})
        health_issues = state.get("health_issues", "")
        expert_advice = state.get("expert_advice", "")
        
        report = f"""# Plant Analysis Report
## Detection Results
- Plant Type: {{plant_info.get('plant_type', 'Unknown')}}
- Health Assessment: {{health_issues}}
## Expert Recommendations
{{expert_advice}}
"""                 
        return {{"final_report": report}}
    
    def retrieve_memory_agent(state: PlantAnalysisState) -> dict:
        try:
            if not memory_client:
                return {{
                    "final_report": "# Memory Error\\\\nMemory client not initialized",
                    "memory_status": "error"
                }}

            events = memory_client.list_events(
                memory_id=MEMORY_ID,
                actor_id=ACTOR_ID,
                session_id=SESSION_ID,
                max_results=10
            )

            if events:
                history_summary = "# Plant Analysis History\\\\n\\\\n"
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
                                # Extract full advice content - don't truncate
                                advice_summary = content.strip()
                                # Remove newline escapes for better display
                                advice_summary = advice_summary.replace('\\\\n', ' ').replace('\\n', ' ')
                                # Limit length but keep more content
                                if len(advice_summary) > 300:
                                    advice_summary = advice_summary[:300] + "..."
                    
                    history_summary += f"**{{i}}. {{formatted_time}}**\\\\n"
                    history_summary += f"   Plant: {{plant_info}}\\\\n"
                    history_summary += f"   Advice: {{advice_summary}}\\\\n\\\\n"

            else:
                history_summary = "# Plant Analysis History\\\\n\\\\nNo previous analyses found."

            return {{
                "final_report": history_summary,
                "memory_status": "retrieved"
            }}
        except Exception as e:
            return {{
                "final_report": f"# Memory Error\\\\n\\\\nCould not retrieve history: {{str(e)}}",
                "memory_status": "error"
            }}

    def save_memory_agent(state: PlantAnalysisState) -> dict:
        try:
            plant_info = state.get("plant_detection", {{}})
            health_issues = state.get("health_issues", "")
            expert_advice = state.get("expert_advice", "")
            conversation = [
                (f"Plant analysis for {{plant_info.get('plant_type', 'unknown plant')}}", "USER"),
                (f"Plant: {{plant_info.get('plant_type')}}\\\\nHealth: {{health_issues}}\\\\nAdvice: {{expert_advice}}", "ASSISTANT")
            ]
            memory_client.save_conversation(
                memory_id=MEMORY_ID,
                actor_id=ACTOR_ID,
                session_id=SESSION_ID,
                messages=conversation
            )
            current_report = state.get("final_report", "")
            enhanced_report = current_report + "\\\\n\\\\n*Analysis saved to memory*"
            
            return {{
                "final_report": enhanced_report,
                "memory_status": "saved"
            }}
        except Exception as e:
            current_report = state.get("final_report", "")
            enhanced_report = current_report + f"\\\\n\\\\n*Memory save failed: {{str(e)}}*"
            return {{
                "final_report": enhanced_report,
                "memory_status": f"save_failed: {{str(e)}}"
            }}
  
    def get_nova_act_api_key(secret_name: str = "nova-act-api-key", region: str = None) -> str:
        """
        Retrieve Nova-Act API key from Secrets Manager.
        Region defaults to Lambda's region if not specified.
        """
        if region is None:
            region = os.environ.get('AWS_REGION', os.environ.get('AWS_DEFAULT_REGION', 'us-east-1'))
        try:
            session = boto3.session.Session()
            client = session.client(service_name='secretsmanager', region_name=region)            
            logger.info(f"🔐 Retrieving Nova-Act API key from AWS Secrets Manager...")
            response = client.get_secret_value(SecretId=secret_name)
            secret_dict = json.loads(response['SecretString'])
            
            api_key = secret_dict.get('nova_act_api_key')
            if not api_key:
                raise ValueError("nova_act_api_key not found in secret")
            
            logger.info("✅ Nova-Act API key retrieved successfully")
            return api_key
        except Exception as exc:
            logger.warning(f"⚠️ Nova-Act API key not available: {{str(exc)}}")
            logger.warning("⚠️ Automatic ordering feature will be disabled")
            return "NOT_CONFIGURED"  # Return placeholder instead of raising

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
Complete Amazon checkout for fertilizer product: {{product_name}}

CURRENT STATE: You are on Amazon homepage and user should be logged in

CHECKOUT STEPS:
1. You are already on Amazon's homepage (https://www.amazon.com/ref=ap_frn_logo)
2. Verify you can see the user's name in the top right (confirming login)
3. Find the search box and search for: {{product_name}}
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
                preview={{"playwright_actuation": True}},
                nova_act_api_key=get_nova_act_api_key(region=REGION), 
                starting_page="https://www.amazon.com/ref=ap_frn_logo",
            ) as nova_act_session:
                logger.info(f"✅ Browser session created for monitoring and checkout")
                
                login_detected = False
                for check_num in range(1, max_checks + 1):
                    logger.info(f"Check {{check_num}}/{{max_checks}}: Checking login status...")     
                    if check_num > 1:
                        time.sleep(2)
                    try:
                        result = nova_act_session.act(login_check_prompt)
                        login_status = result.response
                        logger.info(f"Login status: {{login_status}}")
                        
                        if "LOGIN_COMPLETE" in login_status:
                            logger.info("✅ User name detected - login complete!")
                            login_detected = True
                            break
                    except Exception as e:
                        logger.error(f"Login check error: {{str(e)[:100]}}...")
                    
                    if check_num < max_checks:
                        logger.info(f"⏳ No user name visible yet, waiting 5 seconds... ({{check_num * 5}}s elapsed)")
                        time.sleep(5)
                    else:
                        logger.warning(f"⚠️ Maximum wait time reached ({{max_wait_minutes}} minutes)")
                        logger.warning("Proceeding with checkout anyway...")
                        break
                
                logger.info("🛒 Continuing with fertilizer checkout in the same browser tab...")
                logger.info("👀 Watch the checkout process continue in the same window!")
                time.sleep(3)
                
                try:  
                    checkout_result = nova_act_session.act(checkout_prompt)
                    logger.info(f"Checkout result: {{checkout_result.response}}")
                    
                    return {{
                        'login_detected': login_detected,
                        'checkout_result': checkout_result.response,
                        'status': 'completed'
                    }}
                except Exception as checkout_error:
                    logger.error(f"⚠️ Checkout error: {{str(checkout_error)[:100]}}...")
                    return {{
                        'login_detected': login_detected,
                        'checkout_result': f'Checkout initiated for {{product_name}}. Error: {{str(checkout_error)[:100]}}',
                        'status': 'error'
                    }}
        except Exception as e:
            logger.error(f"❌ Error in monitoring/checkout session: {{str(e)[:100]}}...")
            return {{
                'login_detected': False,
                'checkout_result': f'Session error: {{str(e)[:100]}}',
                'status': 'error'
            }}

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
                name=f"plant-analysis-{{uuid.uuid4().hex[:8]}}",
                session_timeout_seconds=1800
            )
            
            self.ws_url, self.headers = self.browser_client.generate_ws_headers()
            logger.info(f"✅ WebSocket credentials generated")     
            
            session_match = re.search(r'/sessions/([A-Z0-9]+)', self.ws_url)
            if session_match:
                self.session_id = session_match.group(1)
                logger.info(f"✅ Enhanced session created: {{self.session_id}}")
            
            return self.browser_client, self.ws_url, self.headers, self.session_id
        
        def cleanup(self):
            self.session_id = None
            self.browser_client.stop()

    def automatic_order_agent(state: PlantAnalysisState) -> dict:
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
                    if (msg.get('conversational', {{}}).get('role') == 'ASSISTANT'):
                        content = msg['conversational']['content']['text']
                        if 'Fertilizer: ' in content:
                            fertilizer_product = content.split('Fertilizer: ')[1].strip()
                            break
                    break
        except Exception as e:
            logger.error(f"Failed to get fertilizer from memory: {{e}}")
        
        logger.info("🛒 Starting Amazon automation workflow...")
        
        try: 
            session_manager = AsyncBrowserSessionManager(REGION)
            client, ws_url, headers, session_id = session_manager.get_or_create_session()
            
            if session_id:
                live_url = f"https://{{REGION}}.console.aws.amazon.com/bedrock-agentcore/builtInTools/browser/aws.browser.v1/session/{{session_id}}#"
                logger.info(f"🌐 AWS Console Live Session URL: {{live_url}}")
                
                def complete_fertilizer_workflow(session_manager, ws_url, headers, fertilizer_product, session_id):
                    try:
                        logger.info("🔄 BACKGROUND: Starting complete fertilizer ordering workflow...")
                        
                        navigation_prompt = """
Navigate to Amazon sign-in from homepage:

TASK: Check login status and navigate to sign-in if needed

INSTRUCTIONS:
1. You are on the Amazon homepage
2. Look at the top right corner for login status
3. If you see "Hello, Sign in" or just "Sign In", click it to go to login page
4. If you see "Hello, [Name]" with actual user name, return "ALREADY_LOGGED_IN"
5. If you clicked Sign In, return "SIGNIN_PAGE_READY"

Stay focused on the top navigation area only.
"""
                        
                        try:
                            with NovaAct(
                                cdp_endpoint_url=ws_url,
                                cdp_headers=headers,
                                preview={{"playwright_actuation": True}},
                                nova_act_api_key=get_nova_act_api_key(region=REGION),
                                starting_page="https://www.amazon.com/ref=ap_frn_logo",
                            ) as nova_act_nav:
                                logger.info("✅ NOVA-ACT AGENT: AI agent session started")
                                nav_result = nova_act_nav.act(navigation_prompt)
                                print(f"BACKGROUND Navigation result: {{nav_result.response}}")
                        except Exception as nav_error:
                            print("⚠️ BACKGROUND Navigation completed (context change expected)")
                            nav_result = type('obj', (object,), {{'response': 'SIGNIN_PAGE_READY'}})()
                        
                        if "ALREADY_LOGGED_IN" not in str(nav_result.response):
                            print("BACKGROUND Task: Manual login with automated fertilizer checkout...")
                            print("🔐 COMPLETE LOGIN IN BROWSER VIEWER")
                            print(f"🤖 Script will automatically search and order: {{fertilizer_product}}")
                            
                            print("⏳ BACKGROUND: Giving you 10 seconds to complete the login process...")
                            time.sleep(10)
                            
                            result = monitor_login_and_continue_checkout(
                                ws_url, headers, fertilizer_product, max_wait_minutes=8
                            )
                            
                            if result['status'] == 'completed':
                                print("✅ BACKGROUND AGENTCORE WORKFLOW: Plant analysis and fertilizer ordering completed!")
                            else:
                                print("⚠️ BACKGROUND AGENTCORE WORKFLOW: Process completed with issues")
                            
                            print(f"🎉 BACKGROUND AGENTCORE PLANT-TO-PURCHASE COMPLETED!")
                            print("🖥️ BACKGROUND AGENTCORE VIEWER: Staying open for 90 seconds for review...")
                            time.sleep(90)
                        else:
                            print("✅ BACKGROUND AGENTCORE STATUS: User is already logged in!")
                            print("🚀 BACKGROUND AGENTCORE DIRECT: Proceeding to fertilizer checkout...")
                    except Exception as background_error:
                        print(f"❌ BACKGROUND FERTILIZER ORDERING ERROR: {{background_error}}")
                
                background_thread = threading.Thread(
                    target=complete_fertilizer_workflow,
                    args=(session_manager, ws_url, headers, fertilizer_product, session_id),
                    daemon=True,
                    name="CompleteFertilizerWorkflow"
                )
                
                background_thread.start()
                
                return {{
                    'order_status': 'session_started',
                    'live_session_url': live_url,
                    'message': 'Browser session started. Watch the automation at the provided URL.'
                }}
        except Exception as e:
            print(f"Error in Amazon automation workflow: {{e}}")
            return {{'order_status': 'error', 'error': str(e)}}

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
        {{
            "detect_plant": "detect_plant",
            "retrieve_memory": "retrieve_memory",
            "automatic_order": "automatic_order",
            "END": END
        }}
    )
    
    workflow.add_conditional_edges(
        "detect_plant",
        analysis_router,
        {{
            "urgent_consultation": "urgent_consultation",
            "expert_consultation": "expert_consultation",
            "END": END
        }}
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
        log_payload['image_data'] = f"{{log_payload['image_data'][:50]}}... ({{len(log_payload['image_data'])}} chars)"
    
    print(f"📥 Received payload: {{log_payload}}")
    prompt = payload.get("prompt", "")
    image_path = payload.get("image_path", "")
    image_data = payload.get("image_data", "")
    
    history_keywords = ["show me", "previous", "compare", "history", "analyses", "month", "last time"]
    is_history_query = any(keyword in prompt.lower() for keyword in history_keywords) if prompt else False
    
    order_keywords = ["order", "buy", "purchase", "cart", "checkout", "fertilizer"]
    is_ordering_query = any(keyword in prompt.lower() for keyword in order_keywords) if prompt else False
    
    if not is_history_query and not is_ordering_query and not image_path and not image_data:
        return {{"error": "No image_path or image_data provided for plant analysis", "status": "failed"}}
    
    initial_state = {{
        "messages": [],
        "prompt": prompt,
        "query_type": "history" if is_history_query else ("order" if is_ordering_query else "analysis"),
        "image_path": image_path or "from_image_data",
        "image_data": image_data,
        "plant_detection": {{}},
        "health_issues": "",
        "expert_advice": "",
        "recommended_fertilizer": "",
        "web_search_results": "",
        "final_report": "",
        "memory_status": "",
        "order_status": "",
        "live_session_url": "",
        "message": ""
    }}
    
    config = {{"configurable": {{"thread_id": f"agentcore_{{random.randint(1000, 9999)}}"}}}}
    
    try:
        final_state = langgraph_workflow.invoke(initial_state, config)
        
        return {{
            "plant_type": final_state.get('plant_detection', {{}}).get('plant_type', 'Unknown'),
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
        }}
    except Exception as e:
        print(f"Workflow error: {{str(e)}}")
        return {{"error": str(e), "status": "failed"}}

if __name__ == "__main__":
    app.run()
'''

class RuntimeManager:
    """Manages AgentCore runtime operations"""
    def __init__(self, boto3_client, config: RuntimeConfig):
        self.boto3 = boto3_client
        self.config = config
    
    def create_runtime_files(self, project_folder):
        """Create all runtime files"""
        # Create __init__.py
        with open(os.path.join(project_folder, "__init__.py"), 'w') as f:
            f.write('"""Plant Analysis Agent"""\n__version__ = "1.0.0"')
        
        # Create requirements.txt
        with open(os.path.join(project_folder, "requirements.txt"), 'w') as f:
            f.write('boto3\nbotocore\nstrands-agents==1.9.1\nstrands-agents-tools==0.2.9\nstrands-agents-builder\nbedrock-agentcore==1.0.5\nbedrock-agentcore-starter-toolkit\npillow>=10.0.0\nlanggraph>=0.2.0\nlangchain-core>=0.3.0\nlangchain-aws>=0.2.0\npydantic==2.11.10\ntyping-extensions>=4.8.0\nIPython>=8.0.0\nxxhash\nnest-asyncio>=1.5.0\nPillow\npyppeteer\npandas>=1.5.0\nnova-act==2.1.319.0\naws-opentelemetry-distro~=0.12.1\naws-xray-sdk\npython-json-logger\n')
        
        # Create main workflow file with COMPLETE workflow
        generator = WorkflowCodeGenerator(self.config)
        with open(os.path.join(project_folder, "plant_workflow_memory.py"), 'w') as f:
            f.write(generator.generate_complete_workflow())
    
    def create_and_launch_runtime(self, temp_dir):
        """Create and launch AgentCore runtime"""
        from bedrock_agentcore_starter_toolkit.notebook import Runtime
        
        runtime = Runtime()
        config = runtime.configure(
            entrypoint='plant_agent_runtime/plant_workflow_memory.py',
            requirements_file='plant_agent_runtime/requirements.txt',
            agent_name="plant_advisor_agent_v3",
            auto_create_ecr=True,
            execution_role=self.config.runtime_role_arn
        )
            
        runtime_result = runtime.launch(auto_update_on_conflict=True)
        print("AgentCore Runtime result->", runtime_result)
        
        runtime_id = getattr(runtime_result, 'agent_id', 'unknown')
        runtime_arn = getattr(runtime_result, 'agent_arn', 'unknown')
        
        return runtime_id, runtime_arn
        
def send_response(event, context, status, data):
    """Send CloudFormation response"""
    response_body = {
        'Status': status,
        'Reason': f'See CloudWatch Log Stream: {context.log_stream_name}',
        'PhysicalResourceId': data.get('RuntimeId', context.log_stream_name),
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId'],
        'Data': data
    }
    
    http = urllib3.PoolManager()
    response = http.request('PUT', event['ResponseURL'], 
                          body=json.dumps(response_body),
                          headers={'Content-Type': 'application/json'})

def lambda_handler(event, context):
    """Main Lambda handler - refactored but maintains original functionality"""
    try:
        import boto3
        
        if event['RequestType'] == 'Delete':
            region = context.invoked_function_arn.split(':')[3]
            
            runtime_id = event.get('PhysicalResourceId', '')
            if runtime_id and runtime_id != context.log_stream_name:
                cleaner = RuntimeCleaner(boto3, region)
                cleaner.cleanup_and_delete(runtime_id)
            
            send_response(event, context, 'SUCCESS', {})
            return
        
        elif event['RequestType'] == 'Update':                      
            old_runtime_id = event.get('PhysicalResourceId', '')
            print(f"Old runtime ID to cleanup later: {old_runtime_id}")
        
        if event['RequestType'] not in ['Create', 'Update']:
            send_response(event, context, 'SUCCESS', {})
            return
        
        # Extract configuration
        props = event['ResourceProperties']
        cognito_info_raw = json.loads(props['CognitoInfo'])
        cognito_info = cognito_info_raw["authorizer_config"]
        region = context.invoked_function_arn.split(':')[3]
        
        user_pool_id = cognito_info_raw["client_info"]["user_pool_id"]
        region_from_pool = user_pool_id.split('_')[0]
        client_id = cognito_info_raw["client_info"]["client_id"]
        client_secret = cognito_info_raw["client_info"]["client_secret"]
        
        config = RuntimeConfig(
            gateway_id=props['GatewayId'],
            gateway_url=props['GatewayUrl'],
            memory_id=props['MemoryId'],
            memory_role_arn=props['MemoryRoleArn'],
            runtime_role_arn=props['RuntimeRoleArn'],
            region=region,
            client_id=client_id,
            client_secret=client_secret,
            user_pool_id=user_pool_id,
            region_from_pool=region_from_pool,
            cognito_info_raw=cognito_info_raw["client_info"]
        )

        # Create temporary directory for project
        with tempfile.TemporaryDirectory() as temp_dir:
            project_folder = os.path.join(temp_dir, "plant_agent_runtime")
            os.makedirs(project_folder, exist_ok=True)
            
            # Create runtime manager and build files
            manager = RuntimeManager(boto3, config)
            manager.create_runtime_files(project_folder)
            
            # Inject STACK_NAME into the workflow file for secret resolution
            backend_stack_name = props.get('BackendStackName', context.function_name.rsplit('-', 1)[0])
            workflow_file = os.path.join(project_folder, "plant_workflow_memory.py")
            with open(workflow_file, 'r') as f:
                workflow_content = f.read()
            
            # Inject at the top after imports
            injection = f"\nos.environ['STACK_NAME'] = '{backend_stack_name}'\n"
            workflow_content = workflow_content.replace("import boto3\n", f"import boto3\n{injection}")
            
            with open(workflow_file, 'w') as f:
                f.write(workflow_content)
            
            print(f"✅ Injected STACK_NAME into workflow: {backend_stack_name}")
            
            # Change to temp directory for runtime operations
            original_cwd = os.getcwd()
            os.chdir(temp_dir)
            
            try:
                runtime_id, runtime_arn = manager.create_and_launch_runtime(temp_dir)
                
                # Cleanup old runtime if this is an update
                if event['RequestType'] == 'Update':
                    old_runtime_id = event.get('PhysicalResourceId', '')
                    if old_runtime_id and old_runtime_id != context.log_stream_name and old_runtime_id != runtime_id:
                        print(f"Update: Cleaning up old runtime: {old_runtime_id}")
                        try:
                            bedrock_client = boto3.client('bedrock-agentcore-control', region_name=region)
                            bedrock_client.delete_agent_runtime(agentRuntimeId=old_runtime_id)
                            print(f"Successfully cleaned up old runtime: {old_runtime_id}")
                        except Exception as cleanup_error:
                            print(f"Old runtime cleanup failed (non-critical): {cleanup_error}")
                
                send_response(event, context, 'SUCCESS', {
                    'RuntimeId': runtime_id,
                    'RuntimeArn': runtime_arn,
                    'Status': 'deployed'
                })
                
            finally:
                os.chdir(original_cwd)
        
    except Exception as e:
        print(f"Runtime creation error: {str(e)}")
        send_response(event, context, 'FAILED', {'Error': str(e)})
