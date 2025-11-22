# SafePrompt - Prompt Injection Risk Analyzer

A simple web application to analyze AI prompts for security risks and rewrite them safely.

## Features

- 🔍 Analyze prompts for injection risks
- 📊 Risk scoring (0-100)
- 🛡️ Automatic safe prompt generation
- 🎯 Context-aware analysis
- 📋 One-click copy of safe prompts

## Tech Stack

- **Backend**: Python + FastAPI
- **Frontend**: HTML + Bootstrap 5
- **AI**: Anthropic Claude API

## Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Set Up API Key

Copy the example environment file:
```bash
cp .env.example .env
```

Edit `.env` and add your Anthropic API key:
```
ANTHROPIC_API_KEY=sk-ant-...
```

Get your API key from: https://console.anthropic.com/

### 3. Run the Application

```bash
python main.py
```

Or with uvicorn directly:
```bash
uvicorn main:app --reload
```

### 4. Open in Browser

Navigate to: http://localhost:8000

## Usage

1. Select the context where your prompt will be used
2. Paste your prompt in the text area
3. Click "Analyze Prompt"
4. Review the risk assessment and safe version
5. Copy the safe version to use in your application

## API Endpoints

### `POST /analyze`

Analyze a prompt for security risks.

**Request Body:**
```json
{
  "prompt": "Your prompt here",
  "context": "general"
}
```

**Response:**
```json
{
  "risk_level": "Medium",
  "risk_score": 65,
  "issues_found": ["Issue 1", "Issue 2"],
  "explanation": "Detailed explanation...",
  "safe_version": "Safer version of the prompt..."
}
```

### `GET /health`

Health check endpoint.

## Project Structure

```
.
├── main.py              # FastAPI backend
├── index.html           # Frontend UI
├── requirements.txt     # Python dependencies
├── .env.example        # Example environment variables
└── README.md           # This file
```

## Future Enhancements

- [ ] Add more context types
- [ ] Export analysis reports
- [ ] API rate limiting
- [ ] User authentication
- [ ] Batch analysis
- [ ] Historical analysis tracking
- [ ] Custom rule definitions
