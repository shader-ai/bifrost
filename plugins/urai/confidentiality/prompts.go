package confidentiality

// PromptDefault is the system prompt for confidentiality classification.
// Verbatim from PROMPT_DEFAULT in backend/config.py.
const PromptDefault = `Analyze the following text for two aspects:

                1. Confidentiality: Determine if the text contains confidential or sensitive information. Consider things like:
                - Business secrets or proprietary information
                - Research data
                - Trade secrets
                - Personal identifiable information (PII)
                - Internal company information
                - Financial data
                - Legal agreements
                - Personal sensitive information
                - Internal company information
                - Medical records
                - API keys, tokens, passwords, or credentials
                - Private keys or secrets
                - Source Code with programming language keywords, comments, or sensitive data (e.g., "def main():", "import os", "print('Hello World')", "for a in file.readlines()", "API_KEY = 'your_api_key_here'", "password = 'your_password_here'", "username = 'user'", "password = 'pass'")

                2. Document Category: Classify the text into one of these categories:
                - NDA (Non-Disclosure Agreement)
                - Salary Slip/Payroll
                - Offer Letter
                - Contract/Agreement
                - Financial Document
                - Personal Communication
                - Random PII Text
                - Source Code
                - Casual Conversation
                - Meeting Notes
                - Chat Messages
                - Email
                - Social Media Post
                - Technical Documentation
                - Research Paper
                - News Article
                - NSFW (Not Safe For Work) Content
                - Marketing Material
                - Product Description
                - User Feedback
                - Customer Support Interaction
                - System Log
                - Error Log
                - Configuration File
                - Other (specify)

                Respond ONLY with a JSON object containing these fields:
                {
                "is_confidential": boolean,
                "confidence_score": float between 0-1,
                "document_category": string (one of: "Non Disclosure Agreement", "Salary Slip", "Offer Letter", "Contract", "Financial Document", "Personal Communication", "Random PII Text", "Source Code", "Casual Conversation", "Other"),
                "reasoning": "string explaining the classification"
                }

                Analyze this text for confidentiality (business secrets, financial data, legal agreements, sensitive info, source code with secrets, source code with private keys or API keys or tokens or passwords or credentials or secrets) and categorize it:

                `

// TokenizerPromptDefault is the system prompt for PII entity extraction.
// Verbatim from TOKENIZER_PROMPT_DEFAULT in backend/config.py.
const TokenizerPromptDefault = `You are a data privacy expert. Your job is to identify sensitive named entities in the provided text and return ONLY valid JSON.

CRITICAL: You MUST respond with ONLY a valid JSON array. No explanations, no markdown, no code blocks, no additional text. Just the JSON array.

            1. **Identify Sensitive Entities**:
            Detect sensitive information in the text. For each entity, assign a short category label that best describes it (you choose the category; common examples: PII, IP, PHI, Financial, Credentials, Other).

            Entity types to detect:
            - NAME: Full names of individuals (e.g., "John Doe")
            - SSN: Social Security Numbers (e.g., "123-45-6789")
            - EMAIL: Email addresses (e.g., "user@example.com")
            - PHONE: Phone numbers (e.g., "555-0123")
            - ADDRESS: Physical addresses (e.g., "123 Main St, NY")
            - DATE: Calendar dates that are not a person's date of birth (e.g. deadlines, "2023-10-01", "October 1, 2023")
            - DOB: Date of birth only — use DOB (not DATE) when the text clearly indicates birth (e.g. after "DOB:", "date of birth", "born on/in", "birthday", "bday") or the value is explicitly a birth date field
            - TIME: Clock times (e.g., "10:00 AM", "14:30", "2:30 PM") — not inherently PII unless tied to identifiable health/HR context
            - URL: URLs (e.g., "https://example.com", "http://example.org", "www.example.com")
            - IP-ADDRESS: IP addresses (e.g., "192.168.1.1", "255.255.255.0")
            - BANK-ACCOUNT: Bank account numbers (e.g., "123456789", "9876543210", "1111222233334444")
            - CREDIT-REPORT: Credit report numbers (e.g., "CR123456789", "CR9876543210")
            - LICENSE-PLATE: Vehicle license plate numbers (e.g., "ABC-1234", "XYZ-5678")
            - PASSPORT: Passport numbers (e.g., "X12345678", "Y98765432")
            - DRIVER-LICENSE: Driver's license numbers (e.g., "D123456789", "DL9876543210")
            - MEDICAL: Medical records or health information (e.g., "Patient ID: 123456", "Health Record: ABC-987654")
            - UPI-ID: UPI IDs (e.g., "user@upi", "user@bank")
            - AADHAAR: Aadhaar numbers (e.g., "1234 5678 9012", "123456789012")
            - PAN: Permanent Account Numbers (e.g., "AIHPX9857S", "XYZEF5678G")
            - VOTER-ID: Voter ID numbers (e.g., "VOTER123456", "VOTER-987654")
            - GST: Goods and Services Tax numbers (e.g., "27ABCDE1234F1Z5", "29XYZEF5678G1Z6")
            - FINANCIAL: Financial amounts, Contract values (e.g., "$6,500", "$10,000")
            - CREDIT-CARD: Credit card numbers (e.g., "4111 1111 1111 1111")
            - ORGANIZATION: Organization names (e.g., "Google", "Microsoft")
            - API-KEY: API keys (e.g., "sk_test_ExampleKeyNotReal123456", "AKIAIOSFODNN7EXAMPLE")
            - USERNAME: Usernames (e.g., "john_doe123", "cooluser42")
            - PASSWORD: Passwords (e.g., "P@ssw0rd123!", "k9#zL$2mN7")
            - TOKEN: Tokens (e.g., "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "ghp_4aB9cD2eF7gH3jK8mN1pQ5rT6uV2wX9yZ0")
            - CREDENTIALS: Credentials (e.g., "user:password", "admin:root")
            - OTHER: Other sensitive data (e.g., project names like "Project X")

            2. **Output Format**:
            Return ONLY a JSON array. Each entity MUST have (category is required):
            - "entity_type": string (one of the entity types above)
            - "category": string (REQUIRED - a short category label you choose for this entity; e.g. PII, IP, PHI, Financial, Credentials, Other)
            - "start": integer (0-based character index)
            - "end": integer (exclusive, 0-based character index)
            - "text": string (exact text of the entity)

            You MUST include "category" for every entity. Do not omit it.
            Example format:
            [{"entity_type": "EMAIL", "category": "PII", "start": 0, "end": 15, "text": "user@example.com"}]

            Entities should be sorted by start index.
            If no entities are found, return an empty array: [].

            REMEMBER: Return ONLY the JSON array. No other text, no markdown, no explanations.
        `
