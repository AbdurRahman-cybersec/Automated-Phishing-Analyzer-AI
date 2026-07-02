const axios = require('axios');
require('dotenv').config();

async function testOpenRouter() {
    try {
        console.log('🧪 Testing OpenRouter API...\n');

        const response = await axios.post(
            'https://openrouter.ai/api/v1/chat/completions',
            {
                model: process.env.OPENROUTER_MODEL,
                messages: [
                    {
                        role: 'user',
                        content: `Analyze this URL for phishing:
            
URL: disc0rd-verify-account.com
Title: "Verify Your Discord Account NOW"
Login form: Yes (email + password fields)
Text: "Your account will be deleted if you don't verify within 24 hours"

Respond in JSON format:
{
  "verdict": "SAFE" or "PHISHING",
  "confidence": 0-100,
  "reasons": ["reason1", "reason2"]
}`
                    }
                ]
            },
            {
                headers: {
                    'Authorization': `Bearer ${process.env.OPENROUTER_API_KEY}`,
                    'Content-Type': 'application/json'
                }
            }
        );

        const result = response.data.choices[0].message.content;
        console.log('✅ OpenRouter Response:\n');
        console.log(result);
        console.log('\n✅ API key works!\n');

    } catch (error) {
        console.error('❌ Error:', error.response?.data || error.message);
    }
}

testOpenRouter();
