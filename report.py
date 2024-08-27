import streamlit as st
from transformers import pipeline
import re

# Initialize pipelines
sentiment_analyzer = pipeline('sentiment-analysis', model='distilbert-base-uncased-finetuned-sst-2-english')
text_classifier = pipeline('zero-shot-classification', model='facebook/bart-large-mnli')

abuse_types = ['Physical abuse', 'Emotional abuse', 'Sexual abuse', 'Neglect'] 
severity_levels = ['Low', 'Moderate', 'High']

# Function to extract PII and redact it
def extract_pii(report):
    name_pattern = re.compile(r'\b[A-Z][a-z]+\s[A-Z][a-z]+\b')  
    phone_pattern = re.compile(r'\b\d{10}\b|\b\d{3}-\d{3}-\d{4}\b')
    address_pattern = re.compile(r'\d+\s[A-Za-z]+\s(?:St|Ave|Blvd|Rd)\b')
    email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

    pii = {
        'names': name_pattern.findall(report),
        'phones': phone_pattern.findall(report),
        'addresses': address_pattern.findall(report),
        'emails': email_pattern.findall(report)
    }
    
    redacted_report = report
    for key, values in pii.items():
        for value in values:
            redacted_report = redacted_report.replace(value, '[REDACTED]')
    return pii, redacted_report

# Function to classify the severity of the report
def classify_severity(report):
    if 'severe' in report.lower():
        return 'High Severity'
    elif 'moderate' in report.lower():
        return 'Medium Severity'
    else:
        return 'Low Severity'

# Analyze the report to determine abuse type, severity, and recommendations
def analyze_report(report_text):
    sentiment = sentiment_analyzer(report_text) 
    sentiment_score = sentiment[0]['label']
    abuse_type = abuse_classification(report_text)
    severity = determine_severity(sentiment_score, abuse_type)
    recommendations = provide_recommendations(severity)

    return {
        'abuse_type': abuse_type,
        'severity': severity,
        'recommendations': recommendations
    }

# Classify the type of abuse from the report text
def abuse_classification(report_text):
    abuse_classifier = text_classifier(report_text, candidate_labels = abuse_types)
    return abuse_classifier['labels'][0]

# Determine severity based on sentiment score and abuse type
def determine_severity(sentiment_score, abuse_type):
    if sentiment_score in ['POSITIVE', 'NEUTRAL']:
        return 'Low'
    elif sentiment_score == 'NEGATIVE':
        return 'High'
    else:
        return 'Moderate'

# Provide recommendations based on the severity of the case
def provide_recommendations(severity):
    if severity == 'High':
        return 'Immediate action required: Contact authorities and provide support. Please proceed to "Emergency" to contact the relevant authorities if you wish to.'
    elif severity == 'Moderate':
        return 'Consider providing additional support and monitoring. You can proceed to "Consulting" to receive more advice.'
    else:
        return 'Continue to observe and provide general support. You may refer to the "Knowledge Base" to learn more about child abuse and violence.'

# Streamlit app
st.title('Reporting - Abuse Report Analyzer')
report_text = st.text_area("Enter the report text here:")

if st.button('Analyze'):
    if report_text:
        # Extract and redact PII
        pii, redacted_report = extract_pii(report_text)
        st.session_state['pii'] = pii  # Store PII in session state
        st.session_state['redacted_report'] = redacted_report  # Store redacted report

        # Analyze the redacted report
        result = analyze_report(redacted_report)
        
        st.subheader("Analysis Result:")
        st.write(f"**Type of Abuse:** {result['abuse_type']}")
        st.write(f"**Severity:** {result['severity']}")
        st.write(f"**Recommendations:** {result['recommendations']}")
        st.write(f"**Redacted Report:** {redacted_report}")

# Option to reveal PII with password
if 'pii' in st.session_state:
    password = st.text_input("Enter password to view personal identifiable information:", type="password")
    if password == "Police":
        st.subheader("Personal Identifiable Information:")
        pii = st.session_state['pii']  # Retrieve PII from session state
        for key, values in pii.items():
            if values:
                st.write(f"**{key.capitalize()}:** {', '.join(values)}")
    elif password:
        st.error("Incorrect password. PII access denied.")

