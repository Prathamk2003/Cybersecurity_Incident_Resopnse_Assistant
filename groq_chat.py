import os
import sys
import json
from groq import Groq
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def setup_model():
    try:
        api_key = "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"  # Provided Groq API key
        if not api_key:
            raise ValueError("GROQ_API_KEY not found in environment variables")
        # Configure the Groq client
        client = Groq(api_key=api_key)
        return client
    except Exception as e:
        print(json.dumps({"error": str(e), "status": "error"}))
        sys.exit(1)

def get_security_response(client, message):
    try:
        # Add security context to the message
        prompt = f"""As a cybersecurity expert, please provide information about: {message}

Focus on:
- Security implications
- Best practices
- Practical advice
- Clear explanations
- Actionable steps

Keep the response concise and security-focused."""

        messages = [
            {"role": "system", "content": "You are a cybersecurity expert assistant."},
            {"role": "user", "content": prompt}
        ]

        response = client.chat.completions.create(
            messages=messages,
            model="llama3-8b-8192",
            temperature=0.7,
            top_p=0.8,
            # Groq API may not support top_k or safety_settings directly
        )

        content = response.choices[0].message.content if response.choices and response.choices[0].message.content else None
        if not content:
            raise ValueError("Empty response received from model")
        return {
            "response": content,
            "status": "success"
        }
    except Exception as e:
        error_message = str(e)
        suggestion = None
        if 'quota' in error_message.lower():
            suggestion = 'You have exceeded your Groq API quota. Please check your Groq Console quotas and billing.'
        elif 'api key' in error_message.lower():
            suggestion = 'There is an issue with your Groq API key. Please verify it is correct and has access.'
        elif 'Empty response' in error_message:
            suggestion = 'The AI service returned an empty response. Try rephrasing your question or check the service status.'
        return {
            "error": error_message,
            "status": "error",
            "suggestion": suggestion
        }

def main():
    try:
        # Read input
        input_data = sys.stdin.read().strip()
        if not input_data:
            raise ValueError("No input received")
        # Parse input
        data = json.loads(input_data)
        message = data.get("message", "").strip()
        if not message:
            raise ValueError("Empty message received")
        # Setup model
        client = setup_model()
        # Get response
        result = get_security_response(client, message)
        # Print result
        print(json.dumps(result))
        sys.stdout.flush()
    except json.JSONDecodeError:
        print(json.dumps({
            "error": "Invalid JSON input",
            "status": "error"
        }))
    except Exception as e:
        print(json.dumps({
            "error": str(e),
            "status": "error"
        }))

if __name__ == "__main__":
    main() 