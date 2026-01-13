#!/bin/bash

# Plant Advisor Lambda Deployment Script
set -e

# Configuration
RANDOM_SUFFIX=$(python3 -c "import uuid; print(str(uuid.uuid4()).replace('-','')[:8])")
BUCKET_NAME="plant-advisor-lambda-code-${RANDOM_SUFFIX}"
REGION=$(aws configure get region 2>/dev/null || echo "us-east-1")

# Auto-detect Lambda directory (case-insensitive)
if [ -d "Lambda" ]; then
    LAMBDA_DIR="Lambda"
elif [ -d "lambda" ]; then
    LAMBDA_DIR="lambda"
else
    echo "❌ Neither 'Lambda' nor 'lambda' directory found!"
    exit 1
fi
echo "📁 Using Lambda directory: $LAMBDA_DIR"

TEMP_DIR="temp_lambda_packages"

echo "🚀 Starting Lambda deployment process..."

# Validate AWS credentials
echo "🔐 Validating AWS credentials..."
if ! aws sts get-caller-identity &>/dev/null; then
    echo "❌ AWS credentials are not configured or invalid!"
    echo ""
    echo "Please configure AWS credentials using one of these methods:"
    echo "  1. Run: aws configure"
    echo "  2. Set environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY"
    echo "  3. Use AWS SSO: aws sso login"
    echo ""
    exit 1
fi

AWS_ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
AWS_USER=$(aws sts get-caller-identity --query Arn --output text)
echo "✅ AWS credentials validated"
echo "   Account: $AWS_ACCOUNT"
echo "   Identity: $AWS_USER"
echo "   Region: $REGION"
echo ""

# Verify region is valid
if ! aws ec2 describe-regions --region $REGION --query "Regions[?RegionName=='$REGION'].RegionName" --output text &>/dev/null; then
    echo "⚠️  Warning: Unable to verify region $REGION"
    echo "   Continuing anyway..."
fi

# Create temp directory for packaging
mkdir -p $TEMP_DIR

# Function to package Lambda
package_lambda() {
    local function_name=$1
    local source_file="${LAMBDA_DIR}/${function_name}.py"
    local zip_file="${TEMP_DIR}/${function_name}.zip"
    local temp_package_dir="${TEMP_DIR}/${function_name}_package"
    
    echo "📦 Packaging ${function_name}..."
    
    if [ ! -f "$source_file" ]; then
        echo "❌ Source file not found: $source_file"
        exit 1
    fi
    
    # Create temporary package directory
    mkdir -p "$temp_package_dir"
    
    # Copy source file
    cp "$source_file" "$temp_package_dir/"
    
    # Add nova_config.py to functions that need it
    if [[ "$function_name" == "plant_detection" || "$function_name" == "plant_care" || "$function_name" == "websearch" || "$function_name" == "plant_websearch" ]]; then
        if [ -f "${LAMBDA_DIR}/nova_config.py" ]; then
            echo "   📄 Including nova_config.py in ${function_name} package"
            cp "${LAMBDA_DIR}/nova_config.py" "$temp_package_dir/"
        else
            echo "   ⚠️  Warning: nova_config.py not found"
        fi
    fi
    
    # For runtime_custom_resource, also include workflow_template.py
    if [ "$function_name" = "runtime_custom_resource" ]; then
        if [ -f "${LAMBDA_DIR}/workflow_template.py" ]; then
            echo "   📄 Including workflow_template.py in runtime package"
            cp "${LAMBDA_DIR}/workflow_template.py" "$temp_package_dir/"
        else
            echo "   ⚠️  Warning: workflow_template.py not found"
        fi
    fi
    
    #if grep -q "converse" "$source_file"; then
    #    echo "   📚 ${function_name} ..."
    #    pip install boto3>=1.35.0 botocore>=1.35.0 -t "$temp_package_dir" --quiet
    #fi
    
    # Create zip file
    cd "$temp_package_dir"
    zip -r "../../${zip_file}" . -q
    cd ../..
    
    # Clean up temp directory
    rm -rf "$temp_package_dir"
    
    echo "✅ Packaged ${function_name}.zip"
}

# Create S3 bucket if it doesn't exist
echo "🪣 Checking S3 bucket: $BUCKET_NAME"
if ! aws s3 ls "s3://$BUCKET_NAME" 2>/dev/null; then
    echo "Creating S3 bucket: $BUCKET_NAME in region: $REGION"
    if aws s3 mb "s3://$BUCKET_NAME" --region $REGION 2>&1; then
        echo "✅ S3 bucket created successfully"
    else
        echo "❌ Failed to create S3 bucket"
        echo "This could be due to:"
        echo "  - Bucket name already taken globally"
        echo "  - Insufficient permissions"
        echo "  - Invalid AWS credentials"
        exit 1
    fi
else
    echo "✅ S3 bucket exists: $BUCKET_NAME"
fi

# Package all Lambda functions
echo "📦 Packaging Lambda functions..."
# Custom Resource Functions
package_lambda "codebuild_role"
package_lambda "gateway_custom_resource"
package_lambda "gateway_target_custom_resource"
# memory_custom_resource removed - using native CloudFormation AWS::BedrockAgentCore::Memory
package_lambda "runtime_custom_resource"
package_lambda "cognito_secret_store"
# AgentCore Gateway Target Functions
package_lambda "plant_detection"
package_lambda "plant_care"
package_lambda "weather_forecast"
package_lambda "websearch"
package_lambda "plant_websearch"

# Upload to S3
echo ""
echo "⬆️ Uploading Lambda packages to S3..."
aws s3 sync $TEMP_DIR s3://$BUCKET_NAME/lambda/ --delete

echo "⬆️ Uploading pre-built Lambda layer to S3..."
if [ -d "layers-prebuilt" ]; then
    aws s3 sync layers-prebuilt s3://$BUCKET_NAME/layers-prebuilt/ --delete
    echo "✅ HTTP utilities layer uploaded successfully"
else
    echo "❌ Pre-built layer not found! Run: cd layers/http-utils && pip install -r requirements.txt -t python && cd .. && zip -r ../layers-prebuilt/http-utils.zip http-utils/python/"
    exit 1
fi

echo "⬆️ Uploading CloudFormation templates to S3..."
aws s3 cp plant-advisor-backend.yaml s3://$BUCKET_NAME/
aws s3 cp plant-advisor-ui.yaml s3://$BUCKET_NAME/

echo "📦 Creating ui-source.zip from ui folder..."
if [ -d "ui" ]; then
    zip -r ui-source.zip ui/
    echo "✅ ui-source.zip created successfully"
else
    echo "❌ ui folder not found!"
    exit 1
fi

echo "⬆️ Uploading UI source to S3..."
aws s3 cp ui-source.zip s3://$BUCKET_NAME/

# Clean up
echo "🧹 Cleaning up temporary files..."
rm -rf $TEMP_DIR

echo "✅ Lambda deployment complete!"
echo ""
echo "🔧 Deployment Parameters Setup..."
echo ""

# Prompt for Nova-Act API Key (optional - only needed for automatic ordering feature)
echo "Nova-Act API Key is used for automatic fertilizer ordering via browser automation."
echo "If not provided, plant analysis and care advice will still work."
read -p "Enter Nova-Act API Key (optional, press Enter to skip): " NOVA_ACT_API_KEY
if [ -z "$NOVA_ACT_API_KEY" ]; then
    NOVA_ACT_API_KEY="NOT-CONFIGURED-ORDERING-DISABLED"
    echo "⚠️  Nova-Act API Key not provided - automatic ordering feature will be disabled"
fi

# Prompt for Tavily API Key (optional - falls back to Bedrock)
echo ""
echo "Tavily API Key is used for enhanced web search functionality."
echo "If not provided, the app will use Amazon Bedrock for web search instead."
read -p "Enter Tavily API Key (optional, press Enter to skip): " TAVILY_API_KEY
if [ -z "$TAVILY_API_KEY" ]; then
    TAVILY_API_KEY="NOT-CONFIGURED-USING-BEDROCK-FALLBACK"
    echo "ℹ️  Tavily API Key not provided - will use Bedrock for web search"
fi

# Use AWS CLI configured region for all services including Bedrock
BEDROCK_REGION="$REGION"
echo "ℹ️  Using AWS CLI configured region for all services: $BEDROCK_REGION"

# Generate CloudFront secret (32+ characters)
CLOUDFRONT_SECRET=$(openssl rand -base64 32 | tr -d '/+=' | cut -c1-40)
echo "ℹ️  Generated CloudFront secret header for ALB security"

echo ""
echo "✅ Configuration ready!"
echo "   - Nova-Act API Key: ${NOVA_ACT_API_KEY:0:8}..."
echo "   - Tavily API Key: ${TAVILY_API_KEY:0:8}..."
echo "   - Bedrock Region: $BEDROCK_REGION"
echo "   - CloudFront Secret: ${CLOUDFRONT_SECRET:0:8}..."

echo ""
echo "🚀 Deploying CloudFormation stack..."
aws cloudformation deploy \
  --template-file plant-advisor-main.yaml \
  --stack-name plant-advisor-main \
  --parameter-overrides \
    TemplatesBucketName=$BUCKET_NAME \
    SourceCodeBucket=$BUCKET_NAME \
    TavilyApiKey="$TAVILY_API_KEY" \
    NovaActApiKey="$NOVA_ACT_API_KEY" \
    BedrockRegion="$BEDROCK_REGION" \
    CloudFrontSecretHeader="$CLOUDFRONT_SECRET" \
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM

if [ $? -eq 0 ]; then
    echo "✅ Deployment completed successfully!"
else
    echo "❌ Deployment failed!"
    exit 1
fi
