import uuid
import requests
from flask import Flask, render_template, session, request, redirect, url_for
from flask_session import Session  # https://pythonhosted.org/Flask-Session
import msal
import app_config

#new Imports
import os  
from langchain.chat_models import AzureChatOpenAI  
from langchain.prompts import ChatPromptTemplate, HumanMessagePromptTemplate ,PromptTemplate  
from langchain.schema.messages import SystemMessage  
from dotenv import load_dotenv  
import json  
import uuid  
from langchain.output_parsers import StructuredOutputParser, ResponseSchema  
from azure.cosmos import CosmosClient, PartitionKey, exceptions  
import markdown2
import jwt
from azure.cosmos import CosmosClient, PartitionKey, exceptions
load_dotenv()

app = Flask(__name__)
app.config.from_object(app_config)
Session(app)



OPENAI_API_TYPE = os.getenv("OPENAI_API_TYPE")
OPENAI_API_VERSION = os.getenv("OPENAI_API_VERSION")
OPENAI_API_BASE = os.getenv("OPENAI_API_BASE")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
COSMOS_API_KEY = os.getenv("COSMOS_API_KEY")
COSMOS_DB_NAME = os.getenv("COSMOS_DB_NAME")
COSMOS_CONTAINER = os.getenv("COSMOS_CONTAINER_NAME")
COSMOS_DB_URL = os.getenv("COSMOS_DB_URL")
AZURE_ENDPOINT = os.getenv("AZURE_ENDPOINT")


def count_code_lines(code):
    lines = code.split('\n')
    count = 0
    for line in lines:
        stripped_line = line.strip()
        if stripped_line and not stripped_line.startswith('#'):
            count += 1
    return count

def add_to_cosmos_db(defect_density, total_issues,issue_severity,adherence_to_coding,owasp_sans,username):
    # Initialize Cosmos Client
    url = COSMOS_DB_URL
    key = COSMOS_API_KEY
  
    client = CosmosClient(url, credential=key)

    # Select database
    database_name = 'sparkcode'
    database = client.get_database_client(database_name)

    # Select container
    container_name = 'container1'
    container = database.get_container_client(container_name)

    # Prepare the data
    
    data = {
        'id': str(uuid.uuid4()),
        'DefectDensity': defect_density,
        'TotalIssues': total_issues,
        'Issue Severity' : issue_severity,
        'Adherence to Coding Standards' : adherence_to_coding,
        'OWASP Top 10 and SANS Top 25' : owasp_sans,
        'User Name' : username
        
    }

    # Add data to Cosmos DB
    container.upsert_item(body=data)

prompt = """
    You are Expert Code Reviewer. You will review the given code and provide feedback. 
    Do not hallucinate or make up issues which is not there.
    Please be polite and constructive. Remember to be professional 
    Provide the Issues,Suggestions and its serverities in a tabular way.
    Always look for syntax errors.
    If there any Medium or High Issues you will provide the regenerated code.
    Finally you will give a Rating out of 10 based on below Metrices.
    1.Defect Density: This metric measures the number of defects found per thousand lines of code or function points. This can help you identify how many errors were found during the code review process and give you an idea of the overall quality of the code.
    2. Total issues : This metric measures the number of issues found during the code review process.
    3. Issue Severity: Categorize the issues found during the review based on their severity. For example, you might use categories like 'Critical : 0', 'High:1', 'Medium:1', and 'Low:3'.
    4.Adherence to Coding Standards: This is a measure of how well the code conforms organization's coding standards or best practices.
    5.OWASP Top 10 and SANS Top 25: Check if the code complies with the Open Web Application Security Project (OWASP) Top 10 and SANS Top 25 Most Dangerous Software Errors. These are widely-recognized security guidelines and standards.
    example 
    
```
Defect Density: 2/10 (4 issues in approximately 50 lines of code)
Number of code lines : 68
Total Issues: 4
Issue Severity: 'High:2', 'Medium:1', 'Low:1'
Adherence to Coding Standards: 8/10
OWASP Top 10 and SANS Top 25: Not applicable to the provided code snippet.
```
"""

# Check if necessary environment variables are set
if not all([OPENAI_API_TYPE, OPENAI_API_VERSION, OPENAI_API_BASE, OPENAI_API_KEY]):
    raise EnvironmentError("Required environment variables are not set.")

#function to extract metrices


def extract_metrices(data):
    
    response_schemas = [  
    ResponseSchema(name="Defect Density", description= "ratio of defects per lines of code" ),  
    ResponseSchema(name="Total Issues", description="total number of issues"),  
    ResponseSchema(name="Issue Severity", description="High: number of high severity issues, Medium: number of medium severity issues, Low: number of low severity issues"),  
    ResponseSchema(name="Adherence to Coding Standards", description="rating of adherence to coding standards"),  
    ResponseSchema(name="OWASP Top 10 and SANS Top 25", description="applicability of OWASP Top 10 and SANS Top 25 to the provided code snippet")  
]  

    output_parser = StructuredOutputParser.from_response_schemas(response_schemas)
    format_instructions = output_parser.get_format_instructions()
    llm = AzureChatOpenAI(
        
        
        deployment_name="gpt-4-verdentra",
        model_name="gpt-4-verdentra",
        openai_api_key=OPENAI_API_KEY
        
        
    )
    prompt = ChatPromptTemplate(
    messages=[
        HumanMessagePromptTemplate.from_template("""
                    You are a expert in extracting Information from give context.
                    you will extract these information and its values
                        "Rating: ,
                        Defect Density,
                        Total Issues:,
                        Issue Severity: 'High:', 'Medium:', 'Low:' ,
                        Adherence to Coding Standards: ,
                        OWASP Top 10 and SANS Top 25:,"
                    
                      
                     \n{format_instructions}\n{content}""")
    ],
    input_variables=["content"],
    partial_variables={"format_instructions": format_instructions}
)

    try:
       
        _input = prompt.format_prompt(content = data)
        output = llm(_input.to_messages())
        response = output_parser.parse(output.content)
        
        return response
    except Exception as e:
        return f"An error occurred: {e}"

#function to review code
def review_code(code):
    """
    Function to review code using AzureChatOpenAI
    """
    llm = AzureChatOpenAI(
        deployment_name="gpt-4-verdentra",
        model_name="gpt-4-verdentra",
        openai_api_key=OPENAI_API_KEY,
        
    )

    chat_template = ChatPromptTemplate.from_messages(
        [
            SystemMessage(
                content=(prompt
                )
            ),
            HumanMessagePromptTemplate.from_template("{text}"),
        ]
    )

    try:
        res = llm(chat_template.format_messages(text=code))
        return res
    except Exception as e:
        return f"An error occurred: {e}"

# This section is needed for url_for("foo", _external=True) to automatically
# generate http scheme when this sample is running on localhost,
# and to generate https scheme when it is deployed behind reversed proxy.
# See also https://flask.palletsprojects.com/en/1.0.x/deploying/wsgi-standalone/#proxy-setups
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

@app.route("/", methods=['GET', 'POST'])
def index():
    if  not session.get("user"):
        return redirect(url_for("login"))
    else:
        
        user_name = session.get("user")
        if request.method == 'POST':  
            code = request.form['code']  
            client = request.form['client']  
            
            if code:
                feedback = review_code(code)  
                metrices = extract_metrices(feedback.content)  
                nol = count_code_lines(code)
                defect_density = metrices["Defect Density"]  
                total_issues = metrices["Total Issues"]  
                issue_severity = metrices["Issue Severity"]  
                adherence_to_coding_standards = metrices["Adherence to Coding Standards"]  
                owasp_sans = metrices["OWASP Top 10 and SANS Top 25"]  
                name = user_name.get("name")
                crClient  = client
                # Add defect_density and total_issues to Cosmos DB  
                add_to_cosmos_db(defect_density, total_issues,issue_severity,adherence_to_coding_standards,owasp_sans,name)  
                
                #convert to MD
                
                feedback_md = markdown2.markdown(str(feedback.content), extras=["tables","fenced-code-blocks"])
                
                return render_template('result.html', feedback=feedback_md, metrices=metrices ,nol = nol ,user_name=user_name,version=msal.__version__)  
            else:  
                error_message = "Please paste a code snippet."  
                return render_template('index.html', error_message=error_message, user_name=user_name ,version=msal.__version__)  
    
        else:
            user_name = session.get("user")
            return render_template('index.html',user_name=user_name,version=msal.__version__)  
        # return render_template('index.html', user=session["user"], version=msal.__version__)

@app.route("/login")
def login():
    # Technically we could use empty list [] as scopes to do just sign in,
    # here we choose to also collect end user consent upfront
    session["flow"] = _build_auth_code_flow(scopes=app_config.SCOPE)
    return render_template("login.html", auth_url=session["flow"]["auth_uri"])

@app.route(app_config.REDIRECT_PATH)  # Its absolute URL must match your app's redirect_uri set in AAD
def authorized():
    try:
        cache = _load_cache()
        result = _build_msal_app(cache=cache).acquire_token_by_auth_code_flow(
            session.get("flow", {}), request.args)
        if "error" in result:
            return render_template("auth_error.html", result=result)
        session["user"] = result.get("id_token_claims")
        _save_cache(cache)
    except ValueError:  # Usually caused by CSRF
        pass  # Simply ignore them
    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    session.clear()  # Wipe out user and its token cache from session
    return redirect(  # Also logout from your tenant's web session
        app_config.AUTHORITY + "/oauth2/v2.0/logout" +
        "?post_logout_redirect_uri=" + url_for("index", _external=True))

@app.route("/graphcall")
# def graphcall():
#     token = _get_token_from_cache(app_config.SCOPE)
#     if not token:
#         return redirect(url_for("login"))
#     graph_data = requests.get(  # Use token to call downstream service
#         app_config.ENDPOINT,
#         headers={'Authorization': 'Bearer ' + token['access_token']},
#         ).json()
#     return render_template('display.html', result=graph_data)


def _load_cache():
    cache = msal.SerializableTokenCache()
    if session.get("token_cache"):
        cache.deserialize(session["token_cache"])
    return cache

def _save_cache(cache):
    if cache.has_state_changed:
        session["token_cache"] = cache.serialize()

def _build_msal_app(cache=None, authority=None):
    return msal.ConfidentialClientApplication(
        app_config.CLIENT_ID, authority=authority or app_config.AUTHORITY,
        client_credential=app_config.CLIENT_SECRET, token_cache=cache)

def _build_auth_code_flow(authority=None, scopes=None):
    return _build_msal_app(authority=authority).initiate_auth_code_flow(
        scopes or [],
        redirect_uri=url_for("authorized", _external=True))

# def _get_token_from_cache(scope=None):
#     cache = _load_cache()  # This web app maintains one cache per session
#     cca = _build_msal_app(cache=cache)
#     accounts = cca.get_accounts()
#     if accounts:  # So all account(s) belong to the current signed-in user
#         result = cca.acquire_token_silent(scope, account=accounts[0])
#         _save_cache(cache)
#         return result

app.jinja_env.globals.update(_build_auth_code_flow=_build_auth_code_flow)  # Used in template

if __name__ == "__main__":
    app.run()

